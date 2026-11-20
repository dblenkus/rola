"""Record payments for submission sets through the API."""

import pytest

from rola.entries.models import SubmissionSet
from rola.payments.models import Payment

pytestmark = pytest.mark.django_db


def test_payment_permissions_upsert_and_filter(world):
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    data = {"submission_set": group.pk, "paid": True}
    assert world.client.post("/api/v1/payment", data, format="json").status_code == 403
    world.client.force_authenticate(world.admin)
    assert world.client.post("/api/v1/payment", data, format="json").status_code == 201
    data["paid"] = False
    assert world.client.post("/api/v1/payment", data, format="json").status_code == 201
    assert Payment.objects.count() == 1
    assert not Payment.objects.get().paid
    assert world.client.get("/api/v1/payment", {"paid": "true"}).data["results"] == []
    payment = Payment.objects.get()
    for query in ({"submission_set": group.pk}, {"submission_set__in": f"{group.pk}"}):
        results = world.client.get("/api/v1/payment", query).data["results"]
        assert [row["id"] for row in results] == [payment.pk]
