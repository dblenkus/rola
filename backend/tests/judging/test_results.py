"""Publish contest results without revealing private entry details."""

from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from rola.entries.models import Author, Submission, SubmissionSet
from rola.judging.models import (
    AuthorReward,
    Judge,
    Rating,
    SubmissionReward,
    ThemeResults,
)
from rola.payments.models import Payment
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
    assert public.get("/api/v1/results/submissions").data["results"] == []
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = public.get("/api/v1/results/submissions")
    assert response.status_code == 200, response.data
    result = response.data["results"][0]
    assert result["accepted"] is True
    assert result["author"]["country"] is None
    assert result["author"]["reward"] is None
    assert result["author"]["reward_theme"] is None
    assert result["reward_kind"] == "Gold"


def test_published_theme_without_results_lists_no_entries(world):
    item = submitted(world)
    pay(item)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    public = APIClient()
    query = {"theme": world.theme.pk}
    assert public.get("/api/v1/results/submissions", query).data["results"] == []
    assert public.get(f"/api/v1/results/submissions/{item.pk}").status_code == 404
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    response = public.get("/api/v1/results/submissions", query)
    assert response.status_code == 200, response.data
    assert [row["id"] for row in response.data["results"]] == [item.pk]
    assert public.get(f"/api/v1/results/submissions/{item.pk}").status_code == 200


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
    response = APIClient().get("/api/v1/results/submissions")
    assert response.status_code == 200, response.data
    author = response.json()["results"][0]["author"]
    assert author["reward"] == "Best author"
    assert author["reward_theme"] == world.theme.pk


@pytest.mark.parametrize("school_visible", [False, True])
@pytest.mark.parametrize("club_visible", [False, True])
def test_results_show_only_the_public_author_details(
    world, school_visible, club_visible
):
    Author.objects.filter(pk=world.author.pk).update(
        email="alice@example.org",
        date_of_birth="2012-03-04",
        school="Primary school",
        mentor="Teacher Name",
        club="Photo club",
        distinction="Distinction",
    )
    accepted = submitted(world)
    pay(accepted)
    declined = submitted(world, title="Not accepted")
    pay(declined)
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    Rating.objects.create(user=world.other, judge=judge, submission=accepted, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.school_visible = school_visible
    world.contest.club_visible = club_visible
    world.contest.save()
    public = APIClient()
    listing = public.get(
        "/api/v1/results/submissions", {"theme": world.theme.pk}
    ).json()["results"]
    details = [
        public.get(f"/api/v1/results/submissions/{item.pk}").json()
        for item in [accepted, declined]
    ]
    rows = listing + details
    assert [(row["id"], row["accepted"]) for row in rows] == [
        (accepted.pk, True),
        (declined.pk, False),
    ] * 2
    authors = [row["author"] for row in rows]
    for author in authors:
        assert author == {
            "id": world.author.pk,
            "first_name": "Alice",
            "last_name": "Photographer",
            "school": "Primary school" if school_visible else None,
            "club": "Photo club" if club_visible else None,
            "country": None,
            "reward": None,
            "reward_theme": None,
        }


def test_results_list_only_paid_entries_with_scores_only_if_accepted(world):
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

    response = APIClient().get("/api/v1/results/submissions", {"theme": world.theme.pk})
    assert response.status_code == 200, response.data
    assert [
        (row["id"], row["accepted"], row["score"]) for row in response.json()["results"]
    ] == [
        (accepted.pk, True, 5),
        (declined.pk, False, None),
    ]


def test_results_reward_entries_whether_or_not_accepted(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    accepted = submitted(world, title="Accepted")
    declined = submitted(world, title="Declined")
    for item, score, kind in [
        (accepted, 5, SubmissionReward.GOLD),
        (declined, 2, SubmissionReward.HONORABLE_MENTION),
    ]:
        pay(item)
        Rating.objects.create(
            user=world.other, judge=judge, submission=item, rating=score
        )
        SubmissionReward.objects.create(submission=item, kind=kind, label=item.title)
    AuthorReward.objects.create(
        author=world.author, theme=world.theme, label="Best author"
    )
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    public = APIClient()

    listing = public.get("/api/v1/results/submissions").json()["results"]
    details = [
        public.get(f"/api/v1/results/submissions/{item.pk}").json()
        for item in [accepted, declined]
    ]
    rows = [
        (
            row["id"],
            row["accepted"],
            row["reward_kind"],
            row["reward_label"],
            row["author"]["reward"],
            row["author"]["reward_theme"],
        )
        for row in listing + details
    ]
    assert (
        rows
        == [
            (accepted.pk, True, "Gold", "Accepted", "Best author", world.theme.pk),
            (
                declined.pk,
                False,
                "Honorable Mention",
                "Declined",
                "Best author",
                world.theme.pk,
            ),
        ]
        * 2
    )


def test_result_pages_list_a_theme_by_primary_key(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    submissions = Submission.objects.bulk_create(
        Submission(
            user=world.owner,
            author=world.author,
            theme=world.theme,
            title=f"Photo {index}",
        )
        for index in range(20)
    )
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(*submissions)
    Payment.objects.create(submission_set=group, paid=True)
    # Scores fall as primary keys rise, so ordering by score would reverse them.
    Rating.objects.bulk_create(
        Rating(user=world.other, judge=judge, submission=item, rating=10 - index // 2)
        for index, item in enumerate(submissions)
    )
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    client = APIClient()
    ids = []
    page = 1
    while page:
        response = client.get(
            "/api/v1/results/submissions",
            {"theme": world.theme.pk, "page_size": 7, "page": page},
        )
        assert response.status_code == 200, response.data
        ids.extend(row["id"] for row in response.data["results"])
        page = page + 1 if response.data["next"] else None

    assert ids == sorted(item.pk for item in submissions)


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

    response = public.get("/api/v1/results/submissions")
    assert response.status_code == 200, response.data
    assert [(row["id"], row["score"]) for row in response.data["results"]] == [
        (paid.pk, 5)
    ]
    assert public.get(f"/api/v1/results/submissions/{paid.pk}").status_code == 200
    assert public.get(f"/api/v1/results/submissions/{unpaid.pk}").status_code == 404


def test_published_submissions_stay_private_to_their_owner(world):
    item = submitted(world)
    item.files.add(photo(world.owner))
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    for account in [world.other, world.admin]:
        world.client.force_authenticate(account)
        assert world.client.get("/api/v1/submissions").data["results"] == []
    world.client.force_authenticate(world.owner)
    response = world.client.get("/api/v1/submissions")
    assert [row["id"] for row in response.data["results"]] == [item.pk]
