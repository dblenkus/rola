"""Keep list serialization queries bounded as related data grows."""

import hashlib
from datetime import timedelta
from types import SimpleNamespace

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from rola.accounts.models import Location
from rola.contests.models import Theme
from rola.entries.models import Author, SubmissionSet
from rola.judging.models import (
    AuthorReward,
    Judge,
    Rating,
    SubmissionReward,
    ThemeResults,
)
from rola.payments.models import Payment
from tests.factories import pay, photo, submitted

pytestmark = pytest.mark.django_db


def _entry(world, judge, index):
    author = Author.objects.create(
        user=world.owner, first_name=f"Author {index}", last_name="Photographer"
    )
    theme = Theme.objects.create(
        contest=world.contest, title=f"Theme {index}", max_photos=4
    )
    submission = submitted(world, author=author, theme=theme, title=f"Photo {index}")
    files = [photo(world.owner), photo(world.owner)]
    submission.files.add(*files)
    group = SubmissionSet.objects.create(
        user=world.owner, author=author, contest=world.contest
    )
    group.submissions.add(submission)
    Payment.objects.create(submission_set=group, paid=True)
    Rating.objects.create(
        user=world.owner, judge=judge, submission=submission, rating=5
    )
    return SimpleNamespace(
        author=author, theme=theme, submission=submission, group=group, files=files
    )


def _assert_submission(data, entry, email, *, with_author=True):
    assert data["id"] == entry.submission.pk
    assert data["title"] == entry.submission.title
    assert data["theme"] == entry.theme.pk
    if with_author:
        assert data["author"]["id"] == entry.author.pk
        assert data["author"]["first_name"] == entry.author.first_name
        assert data["author"]["email"] == email
    else:
        assert "author" not in data
    assert [item["id"] for item in data["files"]] == [file.pk for file in entry.files]
    assert all(item["file"] and item["thumbnail"] for item in data["files"])


@pytest.mark.parametrize(
    "endpoint",
    [
        "contests",
        "submissions",
        "submission-sets",
        "judging/contests",
        "judging/submissions",
    ],
)
def test_list_queries_do_not_grow_with_related_objects(world, endpoint):
    """Adding related rows preserves response content and the query budget."""
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    if endpoint == "submission-sets":
        world.client.force_authenticate(world.admin)
    entries = []
    query_counts = []
    for count in (1, 4):
        start = len(entries)
        entries.extend(_entry(world, judge, i) for i in range(start, start + count))
        with CaptureQueriesContext(connection) as queries:
            response = world.client.get(f"/api/v1/{endpoint}")
        assert response.status_code == 200, response.data
        query_counts.append(len(queries))
        data = response.data["results"]

        if endpoint in ("contests", "judging/contests"):
            assert [item["id"] for item in data] == [world.contest.pk]
            themes = data[0]["themes"]
            assert [theme["id"] for theme in themes] == [
                world.theme.pk,
                *[entry.theme.pk for entry in entries],
            ]
            assert [theme["submission_count"] for theme in themes] == [
                0,
                *[1 for _ in entries],
            ]
            if endpoint == "judging/contests":
                assert [theme["rating_count"] for theme in themes] == [
                    0,
                    *[1 for _ in entries],
                ]
        elif endpoint == "submission-sets":
            assert [item["id"] for item in data] == [
                entry.group.pk for entry in entries
            ]
            for item, entry in zip(data, entries, strict=True):
                assert item["author"]["id"] == entry.author.pk
                assert item["author"]["email"] == world.owner.email
                assert item["contest"] == world.contest.pk
                assert len(item["submissions"]) == 1
                _assert_submission(item["submissions"][0], entry, world.owner.email)
        else:
            expected = entries
            if endpoint == "judging/submissions":
                expected = sorted(
                    entries,
                    key=lambda entry: hashlib.sha1(
                        f"{entry.submission.pk}{world.owner.pk}".encode()
                    ).hexdigest(),
                )
            assert [item["id"] for item in data] == [
                entry.submission.pk for entry in expected
            ]
            for item, entry in zip(data, expected, strict=True):
                _assert_submission(
                    item, entry, None, with_author=endpoint != "judging/submissions"
                )

    assert query_counts[1] == query_counts[0]


def test_judging_counts_keep_payments_and_judges_independent(world):
    """Paid-set joins and other judges cannot multiply the rating count."""
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    other_judge = Judge.objects.create(judge=world.other, contest=world.contest)
    first, second, unpaid = (submitted(world) for _ in range(3))
    for submission in (first, first, second):
        group = SubmissionSet.objects.create(
            user=world.owner, author=world.author, contest=world.contest
        )
        group.submissions.add(submission)
        Payment.objects.create(submission_set=group, paid=True)
    for submission in (first, unpaid):
        Rating.objects.create(
            user=world.owner, judge=judge, submission=submission, rating=5
        )
    for submission in (first, second):
        Rating.objects.create(
            user=world.other, judge=other_judge, submission=submission, rating=3
        )
    empty = Theme.objects.create(contest=world.contest, title="Empty", max_photos=4)

    response = world.client.get("/api/v1/judging/contests")
    assert response.status_code == 200, response.data
    themes = response.data["results"][0]["themes"]
    assert [theme["id"] for theme in themes] == [world.theme.pk, empty.pk]
    assert [theme["submission_count"] for theme in themes] == [3, 0]
    assert [theme["rating_count"] for theme in themes] == [2, 0]

    response = world.client.get("/api/v1/contests")
    assert response.status_code == 200, response.data
    themes = response.data["results"][0]["themes"]
    assert [theme["submission_count"] for theme in themes] == [3, 0]


def _rewarded_result(world, judge, index):
    author = Author.objects.create(user=world.owner, first_name=f"Author {index}")
    AuthorReward.objects.create(author=author, theme=world.theme, label="Best author")
    submission = submitted(world, author=author)
    submission.files.add(photo(world.owner))
    pay(submission)
    Rating.objects.create(judge=judge, submission=submission, rating=5)
    SubmissionReward.objects.create(submission=submission, kind=1, label="Gold")


def test_published_result_queries_do_not_grow_with_submissions(world):
    """Result authors, their countries, rewards and files are loaded up front."""
    world.owner.location = Location.objects.create(
        country="Slovenia", city="Ljubljana", address="", postal_code=""
    )
    world.owner.save()
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    client = APIClient()
    rows_key = {
        "/api/v1/results/submissions": "results",
        f"/api/v1/results/themes/{world.theme.pk}": "submissions",
    }
    query_counts = {url: [] for url in rows_key}
    created = 0
    for count in (1, 4):
        for index in range(created, created + count):
            _rewarded_result(world, judge, index)
        created += count
        for url, key in rows_key.items():
            with CaptureQueriesContext(connection) as queries:
                response = client.get(url)
            assert response.status_code == 200, response.data
            query_counts[url].append(len(queries))
            rows = response.json()[key]
            assert len(rows) == created
            for row in rows:
                assert row["author"]["country"] == "Slovenia"
                assert row["author"]["reward"] == "Best author"
                assert row["author"]["reward_theme"] == world.theme.pk
                assert row["reward_label"] == "Gold"
                assert len(row["files"]) == 1

    for counts in query_counts.values():
        assert counts[1] == counts[0]
