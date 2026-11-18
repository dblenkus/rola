"""Publish contest results without revealing private entry details."""

from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from rola.entries.models import Author
from rola.judging.models import (
    AuthorReward,
    Judge,
    Rating,
    SubmissionReward,
    ThemeResults,
)
from tests.factories import (
    pay,
    photo,
    submitted,
)

pytestmark = pytest.mark.django_db


def test_results_hide_before_publication_and_handle_optional_relations(world):
    item = submitted(world)
    pay(item)
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    Rating.objects.create(user=world.other, judge=judge, submission=item, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    SubmissionReward.objects.create(submission=item, kind=1, label="Gold")
    public = APIClient()
    assert public.get("/api/v1/results/submission").data["results"] == []
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = public.get("/api/v1/results/submission")
    assert response.status_code == 200, response.data
    result = response.data["results"][0]
    assert result["accepted"] is True
    assert result["author"]["country"] is None
    assert result["author"]["reward"] is None
    assert result["author"]["reward_theme"] is None
    assert result["reward_kind"] == "Gold"


def test_published_theme_without_results_returns_not_found(world):
    submitted(world)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = APIClient().get(f"/api/v1/results/theme/{world.theme.pk}")
    assert response.status_code == 404
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    response = APIClient().get(f"/api/v1/results/theme/{world.theme.pk}")
    assert response.status_code == 200, response.data


def test_results_identify_the_rewarded_theme_by_id(world):
    item = submitted(world)
    pay(item)
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    Rating.objects.create(user=world.other, judge=judge, submission=item, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    AuthorReward.objects.create(
        author=world.author, theme=world.theme, label="Best author"
    )
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = APIClient().get("/api/v1/results/submission")
    assert response.status_code == 200, response.data
    author = response.json()["results"][0]["author"]
    assert author["reward"] == "Best author"
    assert author["reward_theme"] == world.theme.pk


@pytest.mark.parametrize("school_show", [False, True])
@pytest.mark.parametrize("club_show", [False, True])
def test_results_show_only_the_public_author_details(world, school_show, club_show):
    Author.objects.filter(pk=world.author.pk).update(
        email="alice@example.org",
        dob="2012-03-04",
        school="Primary school",
        mentor="Teacher Name",
        club="Photo club",
        distinction="Distinction",
    )
    accepted = submitted(world)
    pay(accepted)
    pay(submitted(world, title="Not accepted"))
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    Rating.objects.create(user=world.other, judge=judge, submission=accepted, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.school_show = school_show
    world.contest.club_show = club_show
    world.contest.save()
    public = APIClient()
    theme = public.get(f"/api/v1/results/theme/{world.theme.pk}").json()
    listing = public.get("/api/v1/results/submission").json()["results"]
    detail = public.get(f"/api/v1/results/submission/{accepted.pk}").json()
    authors = [row["author"] for row in theme["submissions"] + listing + [detail]]
    assert len(authors) == 4
    for author in authors:
        assert author == {
            "id": world.author.pk,
            "first_name": "Alice",
            "last_name": "Photographer",
            "school": "Primary school" if school_show else None,
            "club": "Photo club" if club_show else None,
            "country": None,
            "reward": None,
            "reward_theme": None,
        }


def test_theme_results_list_only_paid_entries_without_scores(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    accepted = submitted(world, title="Accepted")
    declined = submitted(world, title="Declined")
    unpaid = submitted(world, title="Unpaid")
    submitted(world, user=world.other, author=world.other_author, title="Unjudged")
    pay(accepted)
    # A second paid set must neither repeat the entry nor add its score twice,
    # which would lift 2 over the threshold of 3.
    pay(declined)
    pay(declined)
    payment = pay(unpaid)
    payment.paid = False
    payment.save()
    for item, score in [(accepted, 5), (declined, 2), (unpaid, 5)]:
        Rating.objects.create(
            user=world.other, judge=judge, submission=item, rating=score
        )
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()

    response = APIClient().get(f"/api/v1/results/theme/{world.theme.pk}")
    assert response.status_code == 200, response.data
    theme = response.json()
    assert [(row["id"], row["accepted"]) for row in theme["submissions"]] == [
        (accepted.pk, True),
        (declined.pk, False),
    ]
    assert theme["submissions_number"] == 2
    for row in theme["submissions"]:
        assert "rating" not in row


def test_submission_results_list_only_paid_entries(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    paid = submitted(world, title="Paid")
    unpaid = submitted(world, title="Unpaid")
    # A second paid set must neither repeat the entry nor add its score twice.
    pay(paid)
    pay(paid)
    for item in [paid, unpaid]:
        Rating.objects.create(user=world.other, judge=judge, submission=item, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    public = APIClient()

    response = public.get("/api/v1/results/submission")
    assert response.status_code == 200, response.data
    assert [(row["id"], row["rating"]) for row in response.data["results"]] == [
        (paid.pk, 5)
    ]
    assert public.get(f"/api/v1/results/submission/{paid.pk}").status_code == 200
    assert public.get(f"/api/v1/results/submission/{unpaid.pk}").status_code == 404


def test_published_submissions_stay_private_to_their_owner(world):
    item = submitted(world)
    item.files.add(photo(world.owner))
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    for account in [world.other, world.admin]:
        world.client.force_authenticate(account)
        assert world.client.get("/api/v1/submission").data["results"] == []
        response = world.client.get(f"/api/v1/submission/{item.pk}")
        assert response.status_code == 404
    world.client.force_authenticate(world.owner)
    response = world.client.get("/api/v1/submission")
    assert [row["id"] for row in response.data["results"]] == [item.pk]


@pytest.mark.parametrize("method", ["patch", "delete"])
def test_published_scores_are_immutable(world, method):
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world)
    pay(item)
    rating = Rating.objects.create(
        judge=judge, user=world.owner, submission=item, rating=4
    )
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = getattr(world.client, method)(
        f"/api/v1/rating/{rating.pk}", {"rating": 1}, format="json"
    )
    assert response.status_code == 403
    rating.refresh_from_db()
    assert rating.rating == 4
