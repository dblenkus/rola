"""Serve judging, ratings and results under ``/api/v1``."""

import queue
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from django.db import connection, transaction
from django.urls import resolve
from django.utils import timezone
from drf_spectacular.generators import SchemaGenerator
from rest_framework.test import APIClient

from rola.contests.models import Contest, Theme
from rola.judging.models import Judge, Rating, ThemeResults
from tests.factories import (
    pay,
    submitted,
    wait_until_blocked_by_this_connection,
)

pytestmark = pytest.mark.django_db

NOT_RATEABLE = {"detail": "There is no submission with this id that you can rate."}
RATINGS_FINAL = {
    "detail": "The results of this contest are published, so its ratings are final."
}


@pytest.fixture(scope="module")
def schema():
    """Generate the API schema the way the offline schema command does."""
    return SchemaGenerator().get_schema(request=None, public=True)


@pytest.fixture
def judge(world):
    """Make the fixture's authenticated account a judge of the fixture contest."""
    return Judge.objects.create(judge=world.owner, contest=world.contest)


@pytest.fixture
def entry(world):
    """Create a paid submission of another entrant in the fixture contest."""
    item = submitted(world, user=world.other, author=world.other_author)
    pay(item)
    return item


def ref(component):
    """Return a reference to a component schema."""
    return {"$ref": f"#/components/schemas/{component}"}


def json_schema(body):
    """Return the JSON schema of a request body or a response."""
    return body["content"]["application/json"]["schema"]


def judging_operations(paths):
    """Return the operations, by path and method, that the judging app serves."""
    operations = {}
    for path, methods in paths.items():
        url = re.sub(r"\{[^}]+\}", "1", path)
        if resolve(url).func.cls.__module__.startswith("rola.judging."):
            for method, operation in methods.items():
                operations[path, method] = operation
    return operations


def rate(client, submission, data):
    """Set the client's rating of a submission."""
    return client.put(f"/api/v1/judging/ratings/{submission}", data, format="json")


def clear(client, submission):
    """Clear the client's rating of a submission."""
    return client.delete(f"/api/v1/judging/ratings/{submission}")


def listed(client, query=None):
    """Return the ids in a list of the client's ratings."""
    response = client.get("/api/v1/judging/ratings", query or {})
    assert response.status_code == 200, response.data
    return [row["id"] for row in response.json()["results"]]


def publish(contest, instant=None):
    """Publish the contest's results at ``instant``, by default a second ago."""
    contest.publish_date = instant or timezone.now() - timedelta(seconds=1)
    contest.save()


def other_contest():
    """Create a second contest, open for judging, with one theme."""
    now = timezone.now()
    contest = Contest.objects.create(
        title="Other contest",
        start_date=now - timedelta(days=1),
        end_date=now + timedelta(days=1),
        publish_date=now + timedelta(days=2),
    )
    return Theme.objects.create(contest=contest, title="Other", max_photos=4)


def test_a_first_put_creates_the_rating_and_a_later_one_replaces_it(
    world, judge, entry
):
    created = rate(world.client, entry.pk, {"rating": 3})

    assert created.status_code == 201, created.data
    rating = Rating.objects.get()
    assert created.json() == {
        "id": rating.pk,
        "created": created.json()["created"],
        "modified": created.json()["modified"],
        "submission": entry.pk,
        "rating": 3,
    }
    assert (rating.judge, rating.user, rating.submission) == (judge, world.owner, entry)

    replaced = rate(world.client, entry.pk, {"rating": 8})

    assert replaced.status_code == 200, replaced.data
    assert replaced.json()["id"] == rating.pk
    assert replaced.json()["created"] == created.json()["created"]
    assert replaced.json()["rating"] == 8
    assert list(
        Rating.objects.values_list("judge", "user", "submission", "rating")
    ) == [(judge.pk, world.owner.pk, entry.pk, 8)]


def test_repeating_a_put_answers_the_same_rating(world, judge, entry):
    first = rate(world.client, entry.pk, {"rating": 6})

    again = rate(world.client, entry.pk, {"rating": 6})

    assert again.status_code == 200, again.data
    assert {**again.json(), "modified": None} == {**first.json(), "modified": None}
    assert list(Rating.objects.values_list("submission", "rating")) == [(entry.pk, 6)]


def test_submissions_the_caller_cannot_rate_answer_the_same_404(world, judge, entry):
    not_judged = submitted(world, theme=other_contest())
    pay(not_judged)
    unpaid = submitted(world, user=world.other, author=world.other_author)
    revoked = submitted(world, user=world.other, author=world.other_author)
    payment = pay(revoked)
    assert rate(world.client, revoked.pk, {"rating": 5}).status_code == 201
    payment.paid = False
    payment.save()

    responses = [
        rate(world.client, submission, {"rating": 9})
        for submission in [999999, not_judged.pk, unpaid.pk, revoked.pk]
    ]

    for response in responses:
        assert response.status_code == 404
        assert response.json() == NOT_RATEABLE
    assert list(Rating.objects.values_list("submission", "rating")) == [(revoked.pk, 5)]


@pytest.mark.parametrize("value", ["abc", "1.5", "-1"])
def test_a_non_numeric_submission_answers_404(world, judge, entry, value):
    response = rate(world.client, value, {"rating": 5})

    assert response.status_code == 404
    assert not Rating.objects.exists()


def test_a_submission_id_beyond_the_database_range_answers_404(world, judge, entry):
    response = rate(world.client, 2**70, {"rating": 5})

    assert response.status_code == 404
    assert not Rating.objects.exists()


def test_published_results_answer_403_and_keep_the_ratings(world, judge, entry):
    rated = rate(world.client, entry.pk, {"rating": 4})
    assert rated.status_code == 201, rated.data
    unrated = submitted(world, user=world.other, author=world.other_author)
    pay(unrated)
    publish(world.contest)

    for submission in [entry.pk, unrated.pk]:
        response = rate(world.client, submission, {"rating": 9})
        assert response.status_code == 403
        assert response.json() == RATINGS_FINAL
    assert list(Rating.objects.values_list("submission", "rating")) == [(entry.pk, 4)]


def test_ratings_close_at_the_publish_instant(world, judge, entry, monkeypatch):
    instant = timezone.now() + timedelta(hours=1)
    publish(world.contest, instant)

    monkeypatch.setattr(timezone, "now", lambda: instant - timedelta(microseconds=1))
    before = rate(world.client, entry.pk, {"rating": 4})
    monkeypatch.setattr(timezone, "now", lambda: instant)
    at = rate(world.client, entry.pk, {"rating": 9})

    assert before.status_code == 201, before.data
    assert at.status_code == 403
    assert at.json() == RATINGS_FINAL
    assert list(Rating.objects.values_list("rating", flat=True)) == [4]


@pytest.mark.parametrize(
    ("data", "error"),
    [
        ({}, ["This field is required."]),
        ({"rating": None}, ["This field may not be null."]),
        ({"rating": "high"}, ["A valid integer is required."]),
        ({"rating": 7.5}, ["A valid integer is required."]),
        ({"rating": 0}, ["Ensure this value is greater than or equal to 1."]),
        ({"rating": 11}, ["Ensure this value is less than or equal to 10."]),
        ({"rating": -1000}, ["Ensure this value is greater than or equal to 1."]),
    ],
)
def test_a_put_without_a_rating_from_1_to_10_answers_400(
    world, judge, entry, data, error
):
    assert rate(world.client, entry.pk, data).json() == {"rating": error}
    assert not Rating.objects.exists()

    Rating.objects.create(judge=judge, user=world.owner, submission=entry, rating=4)
    response = rate(world.client, entry.pk, data)

    assert response.status_code == 400
    assert response.json() == {"rating": error}
    assert list(Rating.objects.values_list("rating", flat=True)) == [4]


def test_the_path_names_the_submission_not_the_body(world, judge, entry):
    other = submitted(world, user=world.other, author=world.other_author)
    pay(other)

    response = rate(world.client, entry.pk, {"rating": 5, "submission": other.pk})

    assert response.status_code == 201, response.data
    assert response.json()["submission"] == entry.pk
    assert list(Rating.objects.values_list("submission", flat=True)) == [entry.pk]


def test_another_judges_rating_is_neither_changed_nor_listed(world, judge, entry):
    other_judge = Judge.objects.create(judge=world.other, contest=world.contest)
    theirs = Rating.objects.create(
        judge=other_judge, user=world.other, submission=entry, rating=2
    )

    response = rate(world.client, entry.pk, {"rating": 7})

    assert response.status_code == 201, response.data
    theirs.refresh_from_db()
    assert (theirs.judge, theirs.user, theirs.rating) == (other_judge, world.other, 2)
    assert listed(world.client) == [response.json()["id"]]


def test_a_delete_clears_the_callers_rating(world, judge, entry):
    rated = rate(world.client, entry.pk, {"rating": 6})
    assert rated.status_code == 201, rated.data

    response = clear(world.client, entry.pk)

    assert response.status_code == 204, response.content
    assert response.content == b""
    assert not Rating.objects.exists()
    assert listed(world.client) == []


def test_a_delete_without_a_rating_answers_204(world, judge, entry):
    rate(world.client, entry.pk, {"rating": 6})
    first = clear(world.client, entry.pk)

    again = clear(world.client, entry.pk)

    assert first.status_code == 204, first.content
    assert again.status_code == 204, again.content
    assert again.content == b""
    assert not Rating.objects.exists()


def test_a_delete_leaves_another_judges_rating_alone(world, judge, entry):
    other_judge = Judge.objects.create(judge=world.other, contest=world.contest)
    theirs = Rating.objects.create(
        judge=other_judge, user=world.other, submission=entry, rating=2
    )
    rate(world.client, entry.pk, {"rating": 7})

    response = clear(world.client, entry.pk)

    assert response.status_code == 204, response.content
    assert list(Rating.objects.values_list("pk", "judge", "rating")) == [
        (theirs.pk, other_judge.pk, 2)
    ]


def test_a_delete_of_a_submission_the_caller_cannot_rate_answers_the_same_404(
    world, judge, entry
):
    not_judged = submitted(world, theme=other_contest())
    pay(not_judged)
    unpaid = submitted(world, user=world.other, author=world.other_author)
    revoked = submitted(world, user=world.other, author=world.other_author)
    payment = pay(revoked)
    assert rate(world.client, revoked.pk, {"rating": 5}).status_code == 201
    payment.paid = False
    payment.save()

    responses = [
        clear(world.client, submission)
        for submission in [999999, not_judged.pk, unpaid.pk, revoked.pk]
    ]

    for response in responses:
        assert response.status_code == 404
        assert response.json() == NOT_RATEABLE
    assert list(Rating.objects.values_list("submission", "rating")) == [(revoked.pk, 5)]


@pytest.mark.parametrize("value", ["abc", "1.5", "-1", str(2**70)])
def test_a_delete_of_an_id_outside_the_path_pattern_answers_404(
    world, judge, entry, value
):
    Rating.objects.create(judge=judge, user=world.owner, submission=entry, rating=4)

    response = clear(world.client, value)

    assert response.status_code == 404
    assert list(Rating.objects.values_list("rating", flat=True)) == [4]


def test_a_delete_after_publication_answers_403_and_keeps_the_rating(
    world, judge, entry
):
    rated = rate(world.client, entry.pk, {"rating": 4})
    assert rated.status_code == 201, rated.data
    unrated = submitted(world, user=world.other, author=world.other_author)
    pay(unrated)
    publish(world.contest)

    for submission in [entry.pk, unrated.pk]:
        response = clear(world.client, submission)
        assert response.status_code == 403
        assert response.json() == RATINGS_FINAL
    assert list(Rating.objects.values_list("submission", "rating")) == [(entry.pk, 4)]


def test_an_anonymous_delete_answers_401_and_keeps_the_rating(world, judge, entry):
    Rating.objects.create(judge=judge, user=world.owner, submission=entry, rating=4)

    response = clear(APIClient(), entry.pk)

    assert response.status_code == 401
    assert list(Rating.objects.values_list("rating", flat=True)) == [4]


def rating_counts(client):
    """Return the caller's rating count of each theme in the judging contests."""
    response = client.get("/api/v1/judging/contests")
    assert response.status_code == 200, response.data
    return {
        theme["id"]: theme["rating_count"]
        for contest in response.json()["results"]
        for theme in contest["themes"]
    }


@pytest.mark.parametrize("recorded_user", ["none", "other"])
def test_the_callers_judge_rows_name_its_ratings_whatever_their_user(
    world, judge, entry, recorded_user
):
    # A rating's user is nullable and need not be the judge's account, for
    # example for a rating made by an organizer or one whose judge changed.
    user = None if recorded_user == "none" else world.other
    mine = Rating.objects.create(judge=judge, user=user, submission=entry, rating=4)
    second = submitted(world, user=world.other, author=world.other_author)
    pay(second)
    other_judge = Judge.objects.create(judge=world.other, contest=world.contest)
    Rating.objects.create(
        judge=other_judge, user=world.owner, submission=second, rating=2
    )

    assert listed(world.client) == [mine.pk]
    assert rating_counts(world.client) == {world.theme.pk: 1}

    response = rate(world.client, entry.pk, {"rating": 9})

    assert response.status_code == 200, response.data
    assert response.json()["id"] == mine.pk
    assert response.json()["rating"] == 9
    assert listed(world.client) == [mine.pk]
    assert rating_counts(world.client) == {world.theme.pk: 1}


@pytest.mark.parametrize("recorded_user", ["none", "other"])
def test_a_delete_clears_the_callers_judge_rows_rating_whatever_its_user(
    world, judge, entry, recorded_user
):
    user = None if recorded_user == "none" else world.other
    Rating.objects.create(judge=judge, user=user, submission=entry, rating=4)

    response = clear(world.client, entry.pk)

    assert response.status_code == 204, response.content
    assert not Rating.objects.exists()
    assert listed(world.client) == []
    assert rating_counts(world.client) == {world.theme.pk: 0}


def test_a_delete_leaves_another_judges_rating_that_records_the_caller(
    world, judge, entry
):
    other_judge = Judge.objects.create(judge=world.other, contest=world.contest)
    theirs = Rating.objects.create(
        judge=other_judge, user=world.owner, submission=entry, rating=2
    )

    response = clear(world.client, entry.pk)

    assert response.status_code == 204, response.content
    assert list(Rating.objects.values_list("pk", "judge", "user", "rating")) == [
        (theirs.pk, other_judge.pk, world.owner.pk, 2)
    ]


def test_the_ratings_list_filters_by_theme_and_submission(world, judge, entry):
    theme = Theme.objects.create(contest=world.contest, title="City", max_photos=4)
    second = submitted(world, user=world.other, author=world.other_author)
    third = submitted(world, user=world.other, author=world.other_author, theme=theme)
    for item in (second, third):
        pay(item)
    ratings = [
        rate(world.client, item.pk, {"rating": 5}).json()["id"]
        for item in (entry, second, third)
    ]

    assert listed(world.client) == ratings
    assert listed(world.client, {"theme": world.theme.pk}) == ratings[:2]
    assert listed(world.client, {"theme": theme.pk}) == ratings[2:]
    assert listed(world.client, {"submission": second.pk}) == [ratings[1]]
    assert listed(world.client, {"theme": theme.pk, "submission": second.pk}) == []


def test_an_account_that_is_not_a_judge_lists_no_ratings(world, judge, entry):
    rate(world.client, entry.pk, {"rating": 5})
    client = APIClient()
    client.force_authenticate(world.other)

    assert listed(client) == []


def test_anonymous_callers_are_refused(world, judge, entry):
    client = APIClient()

    assert client.get("/api/v1/judging/ratings").status_code == 401
    assert rate(client, entry.pk, {"rating": 5}).status_code == 401
    assert client.get("/api/v1/judging/contests").status_code == 401
    assert client.get("/api/v1/judging/submissions").status_code == 401
    assert not Rating.objects.exists()


def test_judges_list_their_contests_and_submissions(world, judge, entry):
    contests = world.client.get("/api/v1/judging/contests")
    submissions = world.client.get(
        "/api/v1/judging/submissions", {"theme": world.theme.pk}
    )

    assert contests.status_code == 200, contests.data
    assert [row["id"] for row in contests.json()["results"]] == [world.contest.pk]
    assert submissions.status_code == 200, submissions.data
    assert [row["id"] for row in submissions.json()["results"]] == [entry.pk]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/judge/contest"),
        ("get", "/api/v1/judge/submission"),
        ("get", "/api/v1/rating"),
        ("post", "/api/v1/rating"),
        ("get", "/api/v1/rating/{rating}"),
        ("put", "/api/v1/rating/{rating}"),
        ("patch", "/api/v1/rating/{rating}"),
        ("delete", "/api/v1/rating/{rating}"),
        ("get", "/api/v1/results/theme/{theme}"),
        ("get", "/api/v1/results/submission"),
        ("get", "/api/v1/results/submission/{submission}"),
    ],
)
def test_removed_judging_paths_are_not_served(world, judge, entry, method, path):
    rating = Rating.objects.create(
        judge=judge, user=world.owner, submission=entry, rating=4
    )
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    # Published, so the old result paths would have answered 200.
    publish(world.contest)

    response = getattr(world.client, method)(
        path.format(rating=rating.pk, theme=world.theme.pk, submission=entry.pk),
        {} if method == "get" else {"submission": entry.pk, "rating": 9},
        format="json",
    )

    assert response.status_code == 404, response.content
    assert list(Rating.objects.values_list("pk", "rating")) == [(rating.pk, 4)]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/v1/judging/ratings"),
        ("get", "/api/v1/judging/ratings/{submission}"),
        ("patch", "/api/v1/judging/ratings/{submission}"),
        ("post", "/api/v1/judging/contests"),
        ("post", "/api/v1/judging/submissions"),
        ("post", "/api/v1/results/submissions"),
        ("put", "/api/v1/results/submissions/{submission}"),
        ("put", "/api/v1/results/themes/{theme}"),
    ],
)
def test_removed_judging_methods_are_not_allowed(world, judge, entry, method, path):
    rating = Rating.objects.create(
        judge=judge, user=world.owner, submission=entry, rating=4
    )

    response = getattr(world.client, method)(
        path.format(submission=entry.pk, theme=world.theme.pk),
        {} if method == "get" else {"submission": entry.pk, "rating": 9},
        format="json",
    )

    assert response.status_code == 405, response.content
    assert list(Rating.objects.values_list("pk", "rating")) == [(rating.pk, 4)]


@pytest.fixture
def results(world):
    """Publish four accepted submissions; the first two tie, keyed by primary key."""
    judges = [
        Judge.objects.create(judge=account, contest=world.contest)
        for account in (world.owner, world.other)
    ]
    scores = {}
    for index, pair in enumerate([(4, 3), (5, 2), (5, 5), (1, 3)]):
        item = submitted(world, title=f"Photo {index}")
        pay(item)
        for judge, score in zip(judges, pair, strict=True):
            Rating.objects.create(
                judge=judge, user=judge.judge, submission=item, rating=score
            )
        scores[item.pk] = sum(pair)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    publish(world.contest)
    return scores


def result_rows(query=None):
    """Return the ids and scores in the list of submission results."""
    response = APIClient().get("/api/v1/results/submissions", query or {})
    assert response.status_code == 200, response.data
    return [(row["id"], row["score"]) for row in response.json()["results"]]


def test_submission_results_expose_the_total_as_score(world, results):
    pk = next(iter(results))
    listing = APIClient().get("/api/v1/results/submissions").json()["results"]
    detail = APIClient().get(f"/api/v1/results/submissions/{pk}").json()

    for row in [*listing, detail]:
        assert row["score"] == results[row["id"]]
        assert "rating" not in row
    theme = APIClient().get(f"/api/v1/results/themes/{world.theme.pk}").json()
    assert [row["id"] for row in theme["submissions"]] == list(results)
    for row in theme["submissions"]:
        assert "score" not in row
        assert "rating" not in row


def test_submission_results_order_by_score_with_ties_by_primary_key(results):
    by_pk = sorted(results.items())

    assert result_rows() == by_pk
    assert result_rows({"ordering": "-score"}) == sorted(
        by_pk, key=lambda row: (-row[1], row[0])
    )
    assert result_rows({"ordering": "score"}) == sorted(
        by_pk, key=lambda row: (row[1], row[0])
    )
    for ignored in ["rating_sum", "-rating_sum", "rating", "-rating"]:
        assert result_rows({"ordering": ignored}) == by_pk


def test_judging_operations_are_the_eight_in_use(schema):
    operations = judging_operations(schema["paths"])

    assert set(operations) == {
        ("/api/v1/judging/contests", "get"),
        ("/api/v1/judging/submissions", "get"),
        ("/api/v1/judging/ratings", "get"),
        ("/api/v1/judging/ratings/{submission}", "put"),
        ("/api/v1/judging/ratings/{submission}", "delete"),
        ("/api/v1/results/themes/{id}", "get"),
        ("/api/v1/results/submissions", "get"),
        ("/api/v1/results/submissions/{id}", "get"),
    }
    queries = {
        key: {item["name"] for item in operation.get("parameters", [])}
        for key, operation in operations.items()
        if not key[0].endswith("}")
    }
    assert queries == {
        ("/api/v1/judging/contests", "get"): {"page", "page_size"},
        ("/api/v1/judging/submissions", "get"): {"page", "page_size", "theme"},
        ("/api/v1/judging/ratings", "get"): {
            "page",
            "page_size",
            "theme",
            "submission",
        },
        ("/api/v1/results/submissions", "get"): {
            "page",
            "page_size",
            "theme",
            "ordering",
        },
    }
    responses = {
        key: json_schema(operation["responses"]["200"])
        for key, operation in operations.items()
        if key[1] != "delete"
    }
    assert responses == {
        ("/api/v1/judging/contests", "get"): ref("PaginatedJudgeContestList"),
        ("/api/v1/judging/submissions", "get"): ref("PaginatedJudgeSubmissionList"),
        ("/api/v1/judging/ratings", "get"): ref("PaginatedRatingList"),
        ("/api/v1/judging/ratings/{submission}", "put"): ref("Rating"),
        ("/api/v1/results/themes/{id}", "get"): ref("ThemeResults"),
        ("/api/v1/results/submissions", "get"): ref("PaginatedSubmissionResultsList"),
        ("/api/v1/results/submissions/{id}", "get"): ref("SubmissionResults"),
    }


def test_the_rating_put_takes_a_submission_id_and_a_rating(schema):
    update = schema["paths"]["/api/v1/judging/ratings/{submission}"]["put"]

    [parameter] = update["parameters"]
    assert (parameter["name"], parameter["in"], parameter["required"]) == (
        "submission",
        "path",
        True,
    )
    assert parameter["schema"] == {"type": "integer"}
    assert update["requestBody"]["content"] == {
        "application/json": {"schema": ref("RatingRequest")}
    }
    assert update["requestBody"]["required"] is True
    assert {
        status: json_schema(response)
        for status, response in update["responses"].items()
    } == {"200": ref("Rating"), "201": ref("Rating")}


def test_the_rating_delete_takes_a_submission_id_and_answers_204(schema):
    destroy = schema["paths"]["/api/v1/judging/ratings/{submission}"]["delete"]

    [parameter] = destroy["parameters"]
    assert (parameter["name"], parameter["in"], parameter["required"]) == (
        "submission",
        "path",
        True,
    )
    assert parameter["schema"] == {"type": "integer"}
    assert "requestBody" not in destroy
    assert list(destroy["responses"]) == ["204"]
    assert "content" not in destroy["responses"]["204"]


def test_judging_components_have_their_names_and_shapes(schema):
    components = schema["components"]["schemas"]

    rating = components["Rating"]
    assert list(rating["properties"]) == [
        "id",
        "created",
        "modified",
        "submission",
        "rating",
    ]
    assert rating["properties"]["submission"] == {"type": "integer", "readOnly": True}
    request = components["RatingRequest"]
    assert list(request["properties"]) == ["rating"]
    assert request["required"] == ["rating"]
    assert "PatchedRatingRequest" not in components
    results = components["SubmissionResults"]["properties"]
    score = dict(results["score"])
    score.pop("description")
    assert score == {"type": "integer", "nullable": True, "readOnly": True}
    assert "rating" not in results
    for name in [
        "JudgeContest",
        "JudgeTheme",
        "JudgeSubmission",
        "ThemeSubmissionResults",
        "ThemeResults",
        "AuthorResults",
        "PaginatedJudgeContestList",
        "PaginatedJudgeSubmissionList",
        "PaginatedRatingList",
        "PaginatedSubmissionResultsList",
    ]:
        assert name in components


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_concurrent_first_puts_leave_one_rating(world):
    Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world, user=world.other, author=world.other_author)
    pay(item)
    first_client, second_client = APIClient(), APIClient()
    first_client.force_authenticate(world.owner)
    second_client.force_authenticate(world.owner)
    backend_pids = queue.SimpleQueue()

    def put_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return rate(second_client, item.pk, {"rating": 8})
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            first = rate(first_client, item.pk, {"rating": 3})
            second = executor.submit(put_on_another_connection)
            # The second request inserts the same judge and submission, waits
            # for the first one's uncommitted rating and then updates it.
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        second = second.result(timeout=10)

    assert first.status_code == 201, first.data
    assert second.status_code == 200, second.data
    assert second.json()["id"] == first.json()["id"]
    assert list(Rating.objects.values_list("submission", "rating")) == [(item.pk, 8)]
