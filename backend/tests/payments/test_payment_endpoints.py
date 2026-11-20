"""Serve the payments of submission sets under ``/api/v1`` to superusers."""

import queue
import re
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import connection, transaction
from django.urls import resolve
from drf_spectacular.generators import SchemaGenerator
from rest_framework.test import APIClient

from rola.entries.models import SubmissionSet
from rola.judging.models import Judge
from rola.payments.models import Payment
from tests.factories import (
    create_user,
    submitted,
    wait_until_blocked_by_this_connection,
)

pytestmark = pytest.mark.django_db


@pytest.fixture(scope="module")
def schema():
    """Generate the API schema the way the offline schema command does."""
    return SchemaGenerator().get_schema(request=None, public=True)


@pytest.fixture
def admin(world):
    """Authenticate the fixture's client as the superuser."""
    world.client.force_authenticate(world.admin)
    return world.client


def ref(component):
    """Return a reference to a component schema."""
    return {"$ref": f"#/components/schemas/{component}"}


def json_schema(body):
    """Return the JSON schema of a request body or a response."""
    return body["content"]["application/json"]["schema"]


def payments_operations(paths):
    """Return the operations, by path and method, that the payments app serves."""
    operations = {}
    for path, methods in paths.items():
        url = re.sub(r"\{[^}]+\}", "1", path)
        if resolve(url).func.cls.__module__.startswith("rola.payments."):
            for method, operation in methods.items():
                operations[path, method] = operation
    return operations


def new_set(world):
    """Create a submission set of the fixture's entrant."""
    return SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )


def put(client, submission_set, data):
    """Set the payment of a submission set."""
    return client.put(f"/api/v1/payments/{submission_set}", data, format="json")


def test_a_first_put_creates_the_payment_and_a_later_one_updates_it(world, admin):
    group = new_set(world)

    created = put(admin, group.pk, {"paid": True})

    assert created.status_code == 201, created.data
    payment = Payment.objects.get()
    assert created.json() == {
        "id": payment.pk,
        "created": created.json()["created"],
        "modified": created.json()["modified"],
        "submission_set": group.pk,
        "paid": True,
    }
    assert (payment.submission_set, payment.paid) == (group, True)

    updated = put(admin, group.pk, {"paid": False})

    assert updated.status_code == 200, updated.data
    assert updated.json()["id"] == payment.pk
    assert updated.json()["created"] == created.json()["created"]
    assert updated.json()["paid"] is False
    assert list(Payment.objects.values_list("submission_set", "paid")) == [
        (group.pk, False)
    ]


def test_repeating_a_put_answers_the_same_payment(world, admin):
    group = new_set(world)
    first = put(admin, group.pk, {"paid": True})

    again = put(admin, group.pk, {"paid": True})

    assert again.status_code == 200, again.data
    assert {**again.json(), "modified": None} == {**first.json(), "modified": None}
    assert list(Payment.objects.values_list("submission_set", "paid")) == [
        (group.pk, True)
    ]


def test_a_payment_keeps_the_superuser_who_created_it(world, admin):
    group = new_set(world)
    put(admin, group.pk, {"paid": True})
    other_admin = APIClient()
    other_admin.force_authenticate(create_user("second", superuser=True))

    response = put(other_admin, group.pk, {"paid": False})

    assert response.status_code == 200, response.data
    assert Payment.objects.get().user == world.admin


def test_the_path_names_the_submission_set_not_the_body(world, admin):
    group, other = new_set(world), new_set(world)

    response = put(admin, group.pk, {"paid": True, "submission_set": other.pk})

    assert response.status_code == 201, response.data
    assert response.json()["submission_set"] == group.pk
    assert list(Payment.objects.values_list("submission_set", flat=True)) == [group.pk]


def test_an_unknown_submission_set_answers_404_and_creates_nothing(world, admin):
    response = put(admin, 999999, {"paid": True})

    assert response.status_code == 404
    assert set(response.json()) == {"detail"}
    assert not Payment.objects.exists()


@pytest.mark.parametrize("value", ["abc", "1.5", "-1", str(2**70)])
def test_a_non_numeric_or_out_of_range_submission_set_answers_404(world, admin, value):
    new_set(world)

    response = put(admin, value, {"paid": True})

    assert response.status_code == 404
    assert not Payment.objects.exists()


@pytest.mark.parametrize(
    ("data", "error"),
    [
        ({}, ["This field is required."]),
        ({"paid": None}, ["This field may not be null."]),
        ({"paid": "maybe"}, ["Must be a valid boolean."]),
        ({"paid": 2}, ["Must be a valid boolean."]),
    ],
)
def test_a_put_without_a_boolean_paid_answers_400(world, admin, data, error):
    group = new_set(world)

    response = put(admin, group.pk, data)

    assert response.status_code == 400
    assert response.json() == {"paid": error}
    assert not Payment.objects.exists()


@pytest.mark.parametrize(
    ("account", "status"), [(None, 401), ("owner", 403), ("admin", 200)]
)
def test_only_superusers_list_payments(world, account, status):
    group = new_set(world)
    Payment.objects.create(submission_set=group, paid=True)
    client = APIClient()
    if account:
        client.force_authenticate(getattr(world, account))

    response = client.get("/api/v1/payments")

    assert response.status_code == status
    if status == 200:
        assert [row["submission_set"] for row in response.json()["results"]] == [
            group.pk
        ]


@pytest.mark.parametrize(("account", "status"), [(None, 401), ("owner", 403)])
def test_only_superusers_set_payments(world, account, status):
    group = new_set(world)
    existing = Payment.objects.create(submission_set=new_set(world), paid=False)
    client = APIClient()
    if account:
        client.force_authenticate(getattr(world, account))

    for target in (group.pk, existing.submission_set_id):
        assert put(client, target, {"paid": True}).status_code == status
    assert list(Payment.objects.values_list("pk", "paid")) == [(existing.pk, False)]


def test_the_list_filters_by_submission_set_ids_only(world, admin):
    groups = [new_set(world) for _ in range(3)]
    payments = [
        Payment.objects.create(submission_set=group, paid=paid)
        for group, paid in zip(groups, [True, False, True], strict=True)
    ]

    def listed(query):
        response = admin.get("/api/v1/payments", query)
        assert response.status_code == 200, response.data
        return [row["id"] for row in response.json()["results"]]

    assert listed({}) == [payment.pk for payment in payments]
    assert listed({"submission_set__in": f"{groups[2].pk},{groups[0].pk}"}) == [
        payments[0].pk,
        payments[2].pk,
    ]
    # Undeclared filters are ignored.
    assert listed({"paid": "true"}) == [payment.pk for payment in payments]
    assert listed({"submission_set": groups[1].pk}) == [
        payment.pk for payment in payments
    ]


def test_the_list_answers_without_a_query_per_payment(
    world, admin, django_assert_num_queries
):
    for _ in range(3):
        Payment.objects.create(submission_set=new_set(world), paid=True)

    # The count and the page.
    with django_assert_num_queries(2):
        response = admin.get("/api/v1/payments")

    assert response.json()["count"] == 3


def test_a_payment_set_through_the_api_admits_the_set_to_judging(world, admin):
    item = submitted(world)
    group = new_set(world)
    group.submissions.add(item)
    Judge.objects.create(judge=world.other, contest=world.contest)
    judge = APIClient()
    judge.force_authenticate(world.other)
    assert judge.get("/api/v1/judging/submissions").json()["results"] == []

    assert put(admin, group.pk, {"paid": True}).status_code == 201

    listed = judge.get("/api/v1/judging/submissions").json()["results"]
    assert [row["id"] for row in listed] == [item.pk]


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_concurrent_first_puts_leave_one_payment(world):
    group = new_set(world)
    first_client, second_client = APIClient(), APIClient()
    first_client.force_authenticate(world.admin)
    second_client.force_authenticate(world.admin)
    backend_pids = queue.SimpleQueue()

    def put_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return put(second_client, group.pk, {"paid": False})
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            first = put(first_client, group.pk, {"paid": True})
            second = executor.submit(put_on_another_connection)
            # The second request inserts the same submission set, waits for
            # the first one's uncommitted payment and then updates it.
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        second = second.result(timeout=10)

    assert first.status_code == 201, first.data
    assert second.status_code == 200, second.data
    assert second.json()["id"] == first.json()["id"]
    assert list(Payment.objects.values_list("submission_set", "paid")) == [
        (group.pk, False)
    ]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/payment"),
        ("post", "/api/v1/payment"),
        ("get", "/api/v1/payment/{payment}"),
        ("put", "/api/v1/payment/{payment}"),
        ("patch", "/api/v1/payment/{payment}"),
        ("delete", "/api/v1/payment/{payment}"),
    ],
)
def test_removed_payment_paths_are_not_served(world, admin, method, path):
    payment = Payment.objects.create(submission_set=new_set(world), paid=False)

    response = getattr(admin, method)(
        path.format(payment=payment.pk),
        {}
        if method == "get"
        else {"submission_set": payment.submission_set_id, "paid": True},
        format="json",
    )

    assert response.status_code == 404, response.content
    assert list(Payment.objects.values_list("pk", "paid")) == [(payment.pk, False)]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/v1/payments"),
        ("get", "/api/v1/payments/{set}"),
        ("patch", "/api/v1/payments/{set}"),
        ("delete", "/api/v1/payments/{set}"),
    ],
)
def test_removed_payment_methods_are_not_allowed(world, admin, method, path):
    payment = Payment.objects.create(submission_set=new_set(world), paid=False)

    response = getattr(admin, method)(
        path.format(set=payment.submission_set_id),
        {}
        if method == "get"
        else {"submission_set": payment.submission_set_id, "paid": True},
        format="json",
    )

    assert response.status_code == 405, response.content
    assert list(Payment.objects.values_list("pk", "paid")) == [(payment.pk, False)]


def test_payments_operations_are_the_two_in_use(schema):
    operations = payments_operations(schema["paths"])

    assert set(operations) == {
        ("/api/v1/payments", "get"),
        ("/api/v1/payments/{submission_set}", "put"),
    }
    listing = operations["/api/v1/payments", "get"]
    assert listing["operationId"] == "payments_list"
    assert {item["name"] for item in listing["parameters"]} == {
        "page",
        "page_size",
        "submission_set__in",
    }
    assert json_schema(listing["responses"]["200"]) == ref("PaginatedPaymentList")

    update = operations["/api/v1/payments/{submission_set}", "put"]
    [parameter] = update["parameters"]
    assert (parameter["name"], parameter["in"], parameter["required"]) == (
        "submission_set",
        "path",
        True,
    )
    assert parameter["schema"] == {"type": "integer"}
    assert update["requestBody"]["content"] == {
        "application/json": {"schema": ref("PaymentRequest")}
    }
    assert update["requestBody"]["required"] is True
    assert {
        status: json_schema(response)
        for status, response in update["responses"].items()
    } == {"200": ref("Payment"), "201": ref("Payment")}


def test_payments_components_have_their_names_and_shapes(schema):
    components = schema["components"]["schemas"]

    payment = components["Payment"]
    assert list(payment["properties"]) == [
        "id",
        "created",
        "modified",
        "submission_set",
        "paid",
    ]
    assert payment["properties"]["submission_set"] == {
        "type": "integer",
        "readOnly": True,
    }
    assert payment["properties"]["paid"] == {"type": "boolean"}
    request = components["PaymentRequest"]
    assert request["properties"] == {"paid": {"type": "boolean"}}
    assert request["required"] == ["paid"]
    assert "PaginatedPaymentList" in components
    assert "PatchedPaymentRequest" not in components
