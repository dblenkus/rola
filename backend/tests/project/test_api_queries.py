"""Order and filter the API lists only by the parameters the schema declares."""

import pytest
from drf_spectacular.generators import SchemaGenerator

from rola.contests.models import Contest
from rola.judging.models import Judge
from rola.payments.models import Payment
from tests.factories import pay, submitted

pytestmark = pytest.mark.django_db


@pytest.fixture(scope="module")
def schema():
    """Generate the API schema the way the offline schema command does."""
    return SchemaGenerator().get_schema(request=None, public=True)


def parameter(schema, path, name):
    """Return the query parameter ``name`` of the list operation at ``path``."""
    [found] = [
        item
        for item in schema["paths"][path]["get"].get("parameters", [])
        if item["name"] == name and item["in"] == "query"
    ]
    return found


def test_only_result_submissions_declare_ordering(schema):
    ordered = {
        path
        for path, operations in schema["paths"].items()
        for operation in operations.values()
        for item in operation.get("parameters", [])
        if item["name"] == "ordering"
    }
    assert ordered == {"/api/v1/results/submission"}


def test_lists_ignore_ordering_outside_results(world):
    Contest.objects.create(
        title="Later",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    pay(submitted(world))
    pay(submitted(world))
    world.client.force_authenticate(world.admin)
    for path, model in [("/api/v1/contests", Contest), ("/api/v1/payment", Payment)]:
        response = world.client.get(path, {"ordering": "-id"})
        assert response.status_code == 200, response.data
        rows = [row["id"] for row in response.data["results"]]
        assert rows == list(model.objects.order_by("pk").values_list("pk", flat=True))
        assert len(rows) == 2


ID_FILTERS = [
    ("/api/v1/submissions", "contest"),
    ("/api/v1/judge/submission", "theme"),
    ("/api/v1/results/submission", "theme"),
    ("/api/v1/submission-sets", "contest"),
    ("/api/v1/rating", "theme"),
    ("/api/v1/rating", "submission"),
    ("/api/v1/payment", "submission_set"),
]
ID_LIST_FILTERS = [("/api/v1/payment", "submission_set__in")]


@pytest.fixture
def caller(world):
    """Return a client that may list every endpoint that ``path`` names."""

    def client(path):
        Judge.objects.get_or_create(judge=world.owner, contest=world.contest)
        if path == "/api/v1/payment":
            world.client.force_authenticate(world.admin)
        return world.client

    return client


@pytest.mark.parametrize(("path", "name"), ID_FILTERS)
def test_id_filters_are_integers(schema, path, name):
    assert parameter(schema, path, name)["schema"] == {"type": "integer"}


# The frontend filters its submissions by contest and the judging and result
# submissions by theme only.
@pytest.mark.parametrize(
    ("path", "name"),
    [
        ("/api/v1/submissions", "theme"),
        ("/api/v1/judge/submission", "contest"),
        ("/api/v1/results/submission", "contest"),
    ],
)
def test_removed_id_filters_are_not_declared(schema, path, name):
    declared = {
        item["name"] for item in schema["paths"][path]["get"].get("parameters", [])
    }
    assert name not in declared


@pytest.mark.parametrize(("path", "name"), ID_LIST_FILTERS)
def test_id_list_filters_are_comma_separated_integers(schema, path, name):
    found = parameter(schema, path, name)
    assert found["schema"] == {"type": "array", "items": {"type": "integer"}}
    assert (found["style"], found["explode"]) == ("form", False)


# 2**40 is beyond the 32-bit primary keys but within the 64-bit filter range.
@pytest.mark.parametrize("value", [999999, 2**40])
@pytest.mark.parametrize(("path", "name"), ID_FILTERS + ID_LIST_FILTERS)
def test_unknown_id_filter_answers_an_empty_list(caller, path, name, value):
    response = caller(path).get(path, {name: value})
    assert response.status_code == 200, response.content
    assert response.data["results"] == []


def test_rating_filter_does_not_reveal_other_accounts_submissions(world, caller):
    client = caller("/api/v1/rating")
    rated = submitted(world, user=world.other, author=world.other_author)
    pay(rated)
    unrated = submitted(world, user=world.other, author=world.other_author)
    response = client.post(
        "/api/v1/rating", {"submission": rated.pk, "rating": 5}, format="json"
    )
    assert response.status_code == 201, response.data
    assert client.get("/api/v1/rating").data["count"] == 1

    answers = [
        client.get("/api/v1/rating", {"submission": pk}) for pk in [unrated.pk, 999999]
    ]
    for response in answers:
        assert response.status_code == 200, response.content
    assert answers[0].data == answers[1].data
    assert answers[0].data["results"] == []


@pytest.mark.parametrize("value", ["abc", "1.5", "99999999999999999999999"])
@pytest.mark.parametrize(("path", "name"), ID_FILTERS)
def test_malformed_id_filter_answers_400(caller, path, name, value):
    response = caller(path).get(path, {name: value})
    assert response.status_code == 400, response.content
    assert list(response.data) == [name]


@pytest.mark.parametrize("value", ["abc", "1,abc", "1,1.5"])
@pytest.mark.parametrize(("path", "name"), ID_LIST_FILTERS)
def test_malformed_id_list_filter_answers_400(caller, path, name, value):
    response = caller(path).get(path, {name: value})
    assert response.status_code == 400, response.content
    assert list(response.data) == [name]
