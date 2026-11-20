"""Rate paid submissions as a judge of the contest."""

import pytest
from rest_framework.test import APIClient

from rola.accounts.models import User
from rola.contests.models import Contest, Theme
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


def test_judging_uses_postgres_ordering_and_scopes_paid_submissions(world):
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world, user=world.other, author=world.other_author)
    group = SubmissionSet.objects.create(
        user=world.other, author=world.other_author, contest=world.contest
    )
    group.submissions.add(item)
    Payment.objects.create(submission_set=group, paid=True)
    unpaid = submitted(world)
    response = world.client.get("/api/v1/judge/submission")
    assert response.status_code == 200, response.data
    assert [row["id"] for row in response.data["results"]] == [item.pk]
    other_theme = Theme.objects.create(
        contest=world.contest, title="Empty", max_photos=4
    )
    response = world.client.get("/api/v1/judge/submission", {"theme": other_theme.pk})
    assert response.data["results"] == []
    for value in [3, 5]:
        response = world.client.post(
            "/api/v1/rating", {"submission": item.pk, "rating": value}, format="json"
        )
        assert response.status_code == 201, response.data
    assert Rating.objects.get(judge=judge, submission=item).rating == 5
    response = world.client.get("/api/v1/rating", {"submission": unpaid.pk})
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
    response = world.client.get("/api/v1/judge/submission")
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
    response = APIClient().get("/api/v1/judge/submission")
    assert response.status_code == 401


def test_deleting_a_judge_answers_409(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    client = APIClient()
    client.force_authenticate(world.admin)

    response = client.delete(f"/api/v1/user/{world.other.id}")

    assert response.status_code == 409
    assert response.data["detail"] == (
        "This account cannot be deleted while other records depend on it."
    )
    assert User.objects.filter(pk=world.other.pk).exists()
    assert Judge.objects.filter(pk=judge.pk).exists()


def test_rating_updates_cannot_move_rating_to_another_contest(world):
    Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world)
    pay(item)
    response = world.client.post(
        "/api/v1/rating", {"submission": item.pk, "rating": 3}, format="json"
    )
    assert response.status_code == 201
    contest = Contest.objects.create(
        title="Other contest",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    theme = Theme.objects.create(contest=contest, title="Other", max_photos=4)
    other = submitted(world, theme=theme)
    pay(other)
    response = world.client.patch(
        f"/api/v1/rating/{response.data['id']}", {"submission": other.pk}, format="json"
    )
    assert response.status_code == 400


def test_ratings_of_unpaid_submissions_are_refused(world):
    Judge.objects.create(judge=world.owner, contest=world.contest)
    refused = {"submission": ["Only paid submissions can be rated."]}
    unpaid = submitted(world, user=world.other, author=world.other_author)
    response = world.client.post(
        "/api/v1/rating", {"submission": unpaid.pk, "rating": 5}, format="json"
    )
    assert response.status_code == 400
    assert response.data == refused
    assert not Rating.objects.exists()

    item = submitted(world, user=world.other, author=world.other_author)
    payment = pay(item)
    response = world.client.post(
        "/api/v1/rating", {"submission": item.pk, "rating": 5}, format="json"
    )
    assert response.status_code == 201, response.data
    rating = Rating.objects.get()
    payment.paid = False
    payment.save()
    revoked = [
        world.client.post(
            "/api/v1/rating", {"submission": item.pk, "rating": 9}, format="json"
        ),
        world.client.patch(f"/api/v1/rating/{rating.pk}", {"rating": 9}, format="json"),
    ]
    for response in revoked:
        assert response.status_code == 400
        assert response.data == refused
    rating.refresh_from_db()
    assert rating.rating == 5


@pytest.mark.parametrize("score", [0, 11, -1000])
def test_rating_scores_outside_1_to_10_are_refused(world, score):
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world)
    pay(item)
    response = world.client.post(
        "/api/v1/rating", {"submission": item.pk, "rating": score}, format="json"
    )
    assert response.status_code == 400
    assert set(response.data) == {"rating"}
    assert not Rating.objects.exists()

    rating = Rating.objects.create(
        judge=judge, user=world.owner, submission=item, rating=4
    )
    response = world.client.patch(
        f"/api/v1/rating/{rating.pk}", {"rating": score}, format="json"
    )
    assert response.status_code == 400
    assert set(response.data) == {"rating"}
    rating.refresh_from_db()
    assert rating.rating == 4
