"""Serve contests and institutions as read-only lists under ``/api/v1``."""

import re
from datetime import timedelta

import pytest
from django.urls import resolve
from django.utils import timezone
from drf_spectacular.generators import SchemaGenerator
from rest_framework.test import APIClient

from rola.contests.models import Contest, Institution, Theme
from tests.factories import submitted

pytestmark = pytest.mark.django_db


@pytest.fixture(scope="module")
def schema():
    """Generate the API schema the way the offline schema command does."""
    return SchemaGenerator().get_schema(request=None, public=True)


def ref(component):
    """Return a reference to a component schema."""
    return {"$ref": f"#/components/schemas/{component}"}


def contest_operations(paths):
    """Return the operations, by path and method, that the contests app serves."""
    operations = {}
    for path, methods in paths.items():
        url = re.sub(r"\{[^}]+\}", "1", path)
        if resolve(url).func.cls.__module__.startswith("rola.contests."):
            for method, operation in methods.items():
                operations[path, method] = operation
    return operations


def query_parameters(operation):
    """Return the names of an operation's query parameters."""
    return {
        item["name"]
        for item in operation.get("parameters", [])
        if item["in"] == "query"
    }


def ids(response):
    """Return the ids of a paginated list response."""
    assert response.status_code == 200, response.data
    return [item["id"] for item in response.data["results"]]


@pytest.fixture
def past(world):
    """Create a contest that has ended."""
    return Contest.objects.create(
        title="Past",
        start_date=timezone.now() - timedelta(days=4),
        end_date=timezone.now() - timedelta(days=2),
    )


def test_anonymous_visitors_list_and_read_contests(world, past):
    client = APIClient()

    assert ids(client.get("/api/v1/contests")) == [world.contest.pk, past.pk]
    detail = client.get(f"/api/v1/contests/{world.contest.pk}")
    assert detail.status_code == 200, detail.data
    assert detail.data["title"] == "Salon"
    assert [theme["id"] for theme in detail.data["themes"]] == [world.theme.pk]


@pytest.mark.parametrize(
    ("value", "expected"), [("true", "contest"), ("false", "past")]
)
def test_contests_filter_by_activity(world, past, value, expected):
    contest = {"contest": world.contest, "past": past}[expected]

    response = APIClient().get("/api/v1/contests", {"is_active": value})

    assert ids(response) == [contest.pk]


def test_anonymous_visitors_list_institutions(db):
    first = Institution.objects.create(kind=Institution.SCHOOL, name="School")
    second = Institution.objects.create(kind=Institution.SCHOOL, name="Elsewhere")

    response = APIClient().get("/api/v1/institutions", {"page_size": 1000})

    assert ids(response) == [first.pk, second.pk]
    row = response.data["results"][0]
    assert set(row) == {"id", "created", "modified", "name", "kind"}
    assert (row["name"], row["kind"]) == ("School", Institution.SCHOOL)


def test_the_submitted_filter_is_ignored(world):
    submitted(world)
    other = Contest.objects.create(
        title="Other",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    Theme.objects.create(contest=other, title="City", max_photos=4)
    expected = [world.contest.pk, other.pk]

    for value in ("true", "false"):
        response = world.client.get("/api/v1/contests", {"submitted": value})
        assert ids(response) == expected


@pytest.mark.parametrize(
    "parameters",
    [
        {"kind": 2},
        {"name": "School"},
        {"name__contains": "zzz"},
        {"name__icontains": "zzz"},
        {"name__iexact": "school"},
        {"name__istartswith": "zzz"},
        {"name__startswith": "zzz"},
    ],
)
def test_institution_filters_are_ignored(db, parameters):
    first = Institution.objects.create(kind=Institution.SCHOOL, name="School")
    second = Institution.objects.create(kind=Institution.SCHOOL, name="Elsewhere")

    response = APIClient().get("/api/v1/institutions", parameters)

    assert ids(response) == [first.pk, second.pk]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/v1/contests"),
        ("put", "/api/v1/contests/{id}"),
        ("patch", "/api/v1/contests/{id}"),
        ("delete", "/api/v1/contests/{id}"),
        ("post", "/api/v1/institutions"),
    ],
)
def test_contest_writes_are_not_allowed_even_for_a_superuser(world, method, path):
    client = APIClient()
    client.force_authenticate(world.admin)
    before = list(Contest.objects.values())
    institutions = Institution.objects.count()

    response = getattr(client, method)(
        path.format(id=world.contest.pk),
        {"title": "Changed", "kind": Institution.SCHOOL, "name": "New"},
        format="json",
    )

    assert response.status_code == 405, response.data
    assert list(Contest.objects.values()) == before
    assert Institution.objects.count() == institutions


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_anonymous_contest_writes_need_an_account(world, method):
    before = list(Contest.objects.values())

    response = getattr(APIClient(), method)(
        f"/api/v1/contests/{world.contest.pk}", {"title": "Changed"}, format="json"
    )

    assert response.status_code == 401, response.data
    assert list(Contest.objects.values()) == before


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/contest"),
        ("post", "/api/v1/contest"),
        ("get", "/api/v1/contest/{id}"),
        ("put", "/api/v1/contest/{id}"),
        ("patch", "/api/v1/contest/{id}"),
        ("delete", "/api/v1/contest/{id}"),
        ("get", "/api/v1/institution"),
    ],
)
def test_removed_contest_paths_are_not_served(world, method, path):
    client = APIClient()
    client.force_authenticate(world.admin)

    response = getattr(client, method)(path.format(id=world.contest.pk), format="json")

    assert response.status_code == 404


def test_contest_operations_are_the_three_reads(schema):
    operations = contest_operations(schema["paths"])

    assert set(operations) == {
        ("/api/v1/contests", "get"),
        ("/api/v1/contests/{id}", "get"),
        ("/api/v1/institutions", "get"),
    }
    responses = {
        key: operation["responses"]["200"]["content"]["application/json"]["schema"]
        for key, operation in operations.items()
    }
    assert responses == {
        ("/api/v1/contests", "get"): ref("PaginatedContestList"),
        ("/api/v1/contests/{id}", "get"): ref("Contest"),
        ("/api/v1/institutions", "get"): ref("PaginatedInstitutionList"),
    }
    assert query_parameters(operations["/api/v1/contests", "get"]) == {
        "is_active",
        "page",
        "page_size",
    }
    assert query_parameters(operations["/api/v1/institutions", "get"]) == {
        "page",
        "page_size",
    }


def test_contest_components_keep_their_names_without_request_bodies(schema):
    components = schema["components"]["schemas"]

    assert components["PaginatedContestList"]["properties"]["results"]["items"] == (
        ref("Contest")
    )
    assert components["PaginatedInstitutionList"]["properties"]["results"][
        "items"
    ] == ref("Institution")
    assert components["Contest"]["properties"]["themes"]["items"] == ref("Theme")
    assert "InstitutionKindEnum" in components
    for removed in ("ContestRequest", "PatchedContestRequest", "ThemeRequest"):
        assert removed not in components


def test_judging_contests_declare_no_contest_filters(schema):
    operation = schema["paths"]["/api/v1/judging/contests"]["get"]

    assert query_parameters(operation) == {"page", "page_size"}
