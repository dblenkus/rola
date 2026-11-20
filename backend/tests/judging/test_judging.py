"""Rate paid submissions as a judge of the contest."""

import pytest
from django.db.models import ProtectedError
from rest_framework.test import APIClient

from rola.accounts.models import User
from rola.contests.models import Theme
from rola.entries.models import SubmissionSet
from rola.judging.models import (
    Judge,
    Rating,
)
from rola.payments.models import Payment
from tests.factories import (
    pay,
    photo,
    submitted,
)

pytestmark = pytest.mark.django_db


def rate(client, submission, rating):
    """Set the client's rating of a submission."""
    return client.put(
        f"/api/v1/judging/ratings/{submission}", {"rating": rating}, format="json"
    )


def test_judging_uses_postgres_ordering_and_scopes_paid_submissions(world):
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world, user=world.other, author=world.other_author)
    group = SubmissionSet.objects.create(
        user=world.other, author=world.other_author, contest=world.contest
    )
    group.submissions.add(item)
    Payment.objects.create(submission_set=group, paid=True)
    unpaid = submitted(world)
    response = world.client.get("/api/v1/judging/submissions")
    assert response.status_code == 200, response.data
    assert [row["id"] for row in response.data["results"]] == [item.pk]
    other_theme = Theme.objects.create(
        contest=world.contest, title="Empty", max_photos=4
    )
    response = world.client.get(
        "/api/v1/judging/submissions", {"theme": other_theme.pk}
    )
    assert response.data["results"] == []
    for value, status in [(3, 201), (5, 200)]:
        response = rate(world.client, item.pk, value)
        assert response.status_code == status, response.data
    assert Rating.objects.get(judge=judge, submission=item).rating == 5
    response = world.client.get("/api/v1/judging/ratings", {"submission": unpaid.pk})
    assert response.data["results"] == []


def test_judges_see_submissions_without_their_authors(world):
    Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world, user=world.other, author=world.other_author)
    item.files.add(photo(world.other))
    group = SubmissionSet.objects.create(
        user=world.other, author=world.other_author, contest=world.contest
    )
    group.submissions.add(item)
    Payment.objects.create(submission_set=group, paid=True)
    response = world.client.get("/api/v1/judging/submissions")
    assert response.status_code == 200, response.data
    [row] = response.json()["results"]
    assert set(row) == {
        "id",
        "created",
        "modified",
        "theme",
        "title",
        "description",
        "files",
    }
    assert [file["id"] for file in row["files"]] == [item.files.get().pk]


def test_anonymous_judge_endpoint_denies_without_server_error(world):
    response = APIClient().get("/api/v1/judging/submissions")
    assert response.status_code == 401


def test_the_account_of_a_judge_cannot_be_deleted(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)

    with pytest.raises(ProtectedError):
        world.other.delete()

    assert User.objects.filter(pk=world.other.pk).exists()
    assert Judge.objects.filter(pk=judge.pk).exists()


def test_ratings_of_unpaid_submissions_are_refused(world):
    Judge.objects.create(judge=world.owner, contest=world.contest)
    refused = {"detail": "There is no submission with this id that you can rate."}
    unpaid = submitted(world, user=world.other, author=world.other_author)
    response = rate(world.client, unpaid.pk, 5)
    assert response.status_code == 404
    assert response.data == refused
    assert not Rating.objects.exists()

    item = submitted(world, user=world.other, author=world.other_author)
    payment = pay(item)
    response = rate(world.client, item.pk, 5)
    assert response.status_code == 201, response.data
    rating = Rating.objects.get()
    payment.paid = False
    payment.save()
    response = rate(world.client, item.pk, 9)
    assert response.status_code == 404
    assert response.data == refused
    rating.refresh_from_db()
    assert rating.rating == 5


@pytest.mark.parametrize("score", [0, 11, -1000])
def test_rating_scores_outside_1_to_10_are_refused(world, score):
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world)
    pay(item)
    response = rate(world.client, item.pk, score)
    assert response.status_code == 400
    assert set(response.data) == {"rating"}
    assert not Rating.objects.exists()

    rating = Rating.objects.create(
        judge=judge, user=world.owner, submission=item, rating=4
    )
    response = rate(world.client, item.pk, score)
    assert response.status_code == 400
    assert set(response.data) == {"rating"}
    rating.refresh_from_db()
    assert rating.rating == 4
