"""Serve authors, photographs, submissions and submission sets under ``/api/v1``."""

import re
from datetime import timedelta

import pytest
from django.urls import resolve
from django.utils import timezone
from drf_spectacular.generators import SchemaGenerator

from rola.contests.models import Contest, Theme
from rola.entries.models import Author, File, Submission, SubmissionSet
from tests.factories import entry, payload, photo, submitted

pytestmark = pytest.mark.django_db

ENTRIES_CLOSED = {"detail": "This contest is not accepting entries."}


@pytest.fixture(scope="module")
def schema():
    """Generate the API schema the way the offline schema command does."""
    return SchemaGenerator().get_schema(request=None, public=True)


def ref(component):
    """Return a reference to a component schema."""
    return {"$ref": f"#/components/schemas/{component}"}


def json_schema(body):
    """Return the JSON schema of a request body or a response."""
    return body["content"]["application/json"]["schema"]


def entries_operations(paths):
    """Return the operations, by path and method, that the entries app serves."""
    operations = {}
    for path, methods in paths.items():
        url = re.sub(r"\{[^}]+\}", "1", path)
        if resolve(url).func.cls.__module__.startswith("rola.entries."):
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


def upload(world, data, **extra):
    """Post an upload request as the fixture's entrant."""
    return world.client.post("/api/v1/submission-sets", data, format="json", **extra)


def nothing_entered():
    """Check that no submission, set or attachment exists."""
    return (
        not Submission.objects.exists()
        and not SubmissionSet.objects.exists()
        and not File.objects.filter(submission__isnull=False).exists()
    )


def test_an_upload_answers_the_set_as_reading_it_does(world):
    city = Theme.objects.create(contest=world.contest, title="City", max_photos=4)
    dawn = entry(world, title="Dawn", description=None)
    dusk = entry(world, theme=city.pk, title="Dusk", description="Evening")
    dusk["files"].append(photo(world.owner).pk)

    response = upload(world, payload(world, dawn, dusk))

    assert response.status_code == 201, response.data
    created = SubmissionSet.objects.get()
    assert response.json() == (
        world.client.get(f"/api/v1/submission-sets/{created.pk}").json()
    )
    body = response.json()
    assert set(body) == {
        "id",
        "created",
        "modified",
        "submissions",
        "author",
        "contest",
    }
    assert body["author"]["id"] == world.author.pk
    assert body["contest"] == world.contest.pk
    assert [item["title"] for item in body["submissions"]] == ["Dawn", "Dusk"]
    assert [item["theme"] for item in body["submissions"]] == [world.theme.pk, city.pk]
    assert [[file["id"] for file in item["files"]] for item in body["submissions"]] == [
        dawn["files"],
        dusk["files"],
    ]
    assert set(body["submissions"][0]) == {
        "id",
        "created",
        "modified",
        "author",
        "theme",
        "title",
        "description",
        "files",
    }
    assert body["submissions"][0]["author"] == body["author"]
    assert created.user == world.owner
    assert created.author == world.author
    assert [item.title for item in created.submissions.order_by("pk")] == [
        "Dawn",
        "Dusk",
    ]
    assert set(Submission.objects.values_list("user", "author")) == {
        (world.owner.pk, world.author.pk)
    }


def test_an_upload_of_one_submission_creates_a_set_of_one(world):
    response = upload(world, payload(world))

    assert response.status_code == 201, response.data
    assert len(response.data["submissions"]) == 1
    assert SubmissionSet.objects.get().submissions.count() == 1


def _other_contest_theme(world):
    contest = Contest.objects.create(
        title="Second",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
        publish_date=world.contest.publish_date,
    )
    return Theme.objects.create(title="Second", contest=contest, max_photos=4)


def _rejected(world, case):
    """Return a request body that breaks the named rule."""
    data = payload(world)
    item = data["submissions"][0]
    if case == "empty":
        data["submissions"] = []
    elif case == "missing_author":
        del data["author"]
    elif case == "unknown_author":
        data["author"] = 999999
    elif case == "other_author":
        data["author"] = world.other_author.pk
    elif case == "unknown_theme":
        item["theme"] = 999999
    elif case == "no_files":
        item["files"] = []
    elif case == "unknown_file":
        item["files"] = [999999]
    elif case == "file_beyond_the_id_range":
        item["files"] = [2**63]
    elif case == "theme_beyond_the_id_range":
        item["theme"] = 2**63
    elif case == "author_beyond_the_id_range":
        data["author"] = 2**63
    elif case == "other_file":
        item["files"] = [photo(world.other).pk]
    elif case == "attached_file":
        File.objects.filter(pk=item["files"][0]).update(submission=submitted(world))
    elif case == "file_twice_in_a_submission":
        item["files"] *= 2
    elif case == "file_in_two_submissions":
        data["submissions"].append(dict(item))
    elif case == "two_contests":
        data["submissions"].append(entry(world, theme=_other_contest_theme(world).pk))
    elif case == "closed_contest":
        world.contest.end_date = timezone.now() - timedelta(hours=1)
        world.contest.save()
    elif case == "too_many_photographs":
        item["files"] = [photo(world.owner).pk for _ in range(5)]
    return data


ID_TOO_LARGE = f"Ensure this value is less than or equal to {2**63 - 1}."
TOO_MANY = 'Too many photographs for the theme "Nature", which accepts 4 per author.'
REJECTIONS = {
    "empty": (
        400,
        {"submissions": {"non_field_errors": ["This list may not be empty."]}},
    ),
    "missing_author": (400, {"author": ["This field is required."]}),
    "unknown_author": (400, {"author": ["Author must exist and belong to you."]}),
    "other_author": (400, {"author": ["Author must exist and belong to you."]}),
    "unknown_theme": (
        400,
        {
            "submissions": {
                "0": {"theme": ['Invalid pk "999999" - object does not exist.']}
            }
        },
    ),
    "author_beyond_the_id_range": (400, {"author": [ID_TOO_LARGE]}),
    "theme_beyond_the_id_range": (
        400,
        {
            "submissions": {
                "0": {"theme": [f'Invalid pk "{2**63}" - object does not exist.']}
            }
        },
    ),
    "file_beyond_the_id_range": (
        400,
        {"submissions": {"0": {"files": {"0": [ID_TOO_LARGE]}}}},
    ),
    "no_files": (
        400,
        {"submissions": {"0": {"files": ["This list may not be empty."]}}},
    ),
    "unknown_file": (
        400,
        {"submissions": {"0": {"files": ["Files must exist and belong to you."]}}},
    ),
    "other_file": (
        400,
        {"submissions": {"0": {"files": ["Files must exist and belong to you."]}}},
    ),
    "attached_file": (
        400,
        {
            "submissions": {
                "0": {"files": ["A file is already attached to another submission."]}
            }
        },
    ),
    "file_twice_in_a_submission": (
        400,
        {"submissions": {"0": {"files": ["Each file may only be used once."]}}},
    ),
    "file_in_two_submissions": (
        400,
        ["Each file may only be used once in a submission set."],
    ),
    "two_contests": (400, ["All submissions must belong to the same contest."]),
    "closed_contest": (403, ENTRIES_CLOSED),
    "too_many_photographs": (400, {"files": [TOO_MANY]}),
}


@pytest.mark.parametrize("case", list(REJECTIONS))
def test_an_upload_that_breaks_a_rule_enters_nothing(world, case):
    data = _rejected(world, case)
    attached = set(File.objects.filter(submission__isnull=False))
    submissions = Submission.objects.count()

    response = upload(world, data)

    status, body = REJECTIONS[case]
    assert response.status_code == status, response.data
    assert response.json() == body
    assert Submission.objects.count() == submissions
    assert not SubmissionSet.objects.exists()
    assert set(File.objects.filter(submission__isnull=False)) == attached


@pytest.mark.parametrize(
    ("change", "body"),
    [
        (
            lambda world, data: data.update(author={"id": world.author.pk}),
            {"author": ["A valid integer is required."]},
        ),
        (
            lambda world, data: data["submissions"][0].update(
                files=[{"id": file} for file in data["submissions"][0]["files"]]
            ),
            {"submissions": {"0": {"files": {"0": ["A valid integer is required."]}}}},
        ),
    ],
    ids=["author", "files"],
)
def test_related_objects_are_plain_ids(world, change, body):
    data = payload(world)
    change(world, data)

    response = upload(world, data)

    assert response.status_code == 400, response.data
    assert response.json() == body
    assert nothing_entered()


def test_the_old_object_or_list_body_is_refused(world):
    item = entry(world)
    item["author"] = world.author.pk

    for data in (item, [item]):
        response = upload(world, data)
        assert response.status_code == 400, response.data
    assert nothing_entered()


def test_authors_are_created_and_answered(world):
    response = world.client.post(
        "/api/v1/authors",
        {"first_name": "New", "last_name": "Author", "date_of_birth": "2000-01-31"},
        format="json",
    )

    assert response.status_code == 201, response.data
    author = Author.objects.get(pk=response.data["id"])
    assert (author.user, author.first_name) == (world.owner, "New")
    assert response.data["email"] is None
    assert response.data["date_of_birth"] == "2000-01-31"


def test_the_submission_list_holds_own_submissions_by_contest(world):
    own = submitted(world)
    submitted(world, user=world.other, author=world.other_author)
    theme = _other_contest_theme(world)
    elsewhere = submitted(world, theme=theme)

    everything = world.client.get("/api/v1/submissions")
    in_contest = world.client.get("/api/v1/submissions", {"contest": world.contest.pk})
    # The removed theme filter is ignored.
    by_theme = world.client.get("/api/v1/submissions", {"theme": theme.pk})

    assert [row["id"] for row in everything.data["results"]] == [own.pk, elsewhere.pk]
    assert [row["id"] for row in in_contest.data["results"]] == [own.pk]
    assert [row["id"] for row in by_theme.data["results"]] == [own.pk, elsewhere.pk]


def test_another_accounts_submission_cannot_be_deleted(world):
    item = submitted(world, user=world.other, author=world.other_author)

    response = world.client.delete(f"/api/v1/submissions/{item.pk}")

    assert response.status_code == 404
    assert Submission.objects.filter(pk=item.pk).exists()


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/author"),
        ("post", "/api/v1/author"),
        ("get", "/api/v1/author/{author}"),
        ("post", "/api/v1/file"),
        ("get", "/api/v1/submission"),
        ("post", "/api/v1/submission"),
        ("get", "/api/v1/submission/{submission}"),
        ("delete", "/api/v1/submission/{submission}"),
        ("get", "/api/v1/submissionset"),
        ("get", "/api/v1/submissionset/{set}"),
        ("delete", "/api/v1/submissionset/{set}"),
        ("get", "/api/v1/authors/{author}"),
        ("put", "/api/v1/authors/{author}"),
        ("patch", "/api/v1/authors/{author}"),
        ("delete", "/api/v1/authors/{author}"),
        ("get", "/api/v1/files/{file}"),
    ],
)
def test_removed_entries_paths_are_not_served(world, method, path):
    item = submitted(world)
    image = photo(world.owner)
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(item)
    url = path.format(
        author=world.author.pk, submission=item.pk, set=group.pk, file=image.pk
    )

    response = getattr(world.client, method)(url, {}, format="json")

    assert response.status_code == 404, response.content
    assert Submission.objects.filter(pk=item.pk).exists()
    assert SubmissionSet.objects.filter(pk=group.pk).exists()


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/authors"),
        ("get", "/api/v1/files"),
        ("post", "/api/v1/submissions"),
        ("get", "/api/v1/submissions/{submission}"),
        ("put", "/api/v1/submissions/{submission}"),
        ("patch", "/api/v1/submissions/{submission}"),
        ("put", "/api/v1/submission-sets/{set}"),
        ("patch", "/api/v1/submission-sets/{set}"),
    ],
)
def test_removed_entries_methods_are_not_allowed(world, method, path):
    item = submitted(world)
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(item)
    url = path.format(submission=item.pk, set=group.pk)

    response = getattr(world.client, method)(url, {"title": "Changed"}, format="json")

    assert response.status_code == 405, response.content
    item.refresh_from_db()
    assert item.title == "Original"


def test_entries_operations_are_the_eight_in_use(schema):
    operations = entries_operations(schema["paths"])

    assert set(operations) == {
        ("/api/v1/authors", "post"),
        ("/api/v1/files", "post"),
        ("/api/v1/submissions", "get"),
        ("/api/v1/submissions/{id}", "delete"),
        ("/api/v1/submission-sets", "post"),
        ("/api/v1/submission-sets", "get"),
        ("/api/v1/submission-sets/{id}", "get"),
        ("/api/v1/submission-sets/{id}", "delete"),
    }
    assert query_parameters(operations["/api/v1/submissions", "get"]) == {
        "contest",
        "page",
        "page_size",
    }
    assert query_parameters(operations["/api/v1/submission-sets", "get"]) == {
        "contest",
        "page",
        "page_size",
    }
    responses = {
        key: json_schema(operation["responses"][status])
        for key, operation in operations.items()
        for status in operation["responses"]
        if status != "204"
    }
    assert responses == {
        ("/api/v1/authors", "post"): ref("Author"),
        ("/api/v1/files", "post"): ref("File"),
        ("/api/v1/submissions", "get"): ref("PaginatedSubmissionList"),
        ("/api/v1/submission-sets", "post"): ref("SubmissionSet"),
        ("/api/v1/submission-sets", "get"): ref("PaginatedSubmissionSetList"),
        ("/api/v1/submission-sets/{id}", "get"): ref("SubmissionSet"),
    }


def test_an_upload_declares_its_body_answers_and_key(schema):
    create = schema["paths"]["/api/v1/submission-sets"]["post"]

    assert create["requestBody"]["content"] == {
        "application/json": {"schema": ref("SubmissionSetCreateRequest")}
    }
    assert create["requestBody"]["required"] is True
    assert {
        status: json_schema(response)
        for status, response in create["responses"].items()
    } == {"200": ref("SubmissionSet"), "201": ref("SubmissionSet")}
    [key] = [item for item in create["parameters"] if item["in"] == "header"]
    assert key["name"] == "Idempotency-Key"
    assert key["schema"] == {"type": "string", "format": "uuid"}
    assert key.get("required", False) is False


def test_entries_components_have_their_names_and_shapes(schema):
    components = schema["components"]["schemas"]

    upload_body = components["SubmissionSetCreateRequest"]
    # Ids beyond the 64-bit range that the databases store answer 400.
    some_id = {
        "type": "integer",
        "maximum": 2**63 - 1,
        "minimum": -(2**63),
        "format": "int64",
    }
    assert upload_body["properties"] == {
        "author": some_id,
        "submissions": {
            "type": "array",
            "items": ref("SubmissionCreateRequest"),
        },
    }
    assert sorted(upload_body["required"]) == ["author", "submissions"]
    item = components["SubmissionCreateRequest"]
    assert set(item["properties"]) == {"theme", "title", "description", "files"}
    assert item["properties"]["theme"] == {"type": "integer"}
    assert item["properties"]["files"] == {"type": "array", "items": some_id}
    assert sorted(item["required"]) == ["files", "theme"]

    submission = components["Submission"]["properties"]
    assert list(submission) == [
        "id",
        "created",
        "modified",
        "author",
        "theme",
        "title",
        "description",
        "files",
    ]
    assert submission["author"] == ref("Author")
    assert submission["files"] == {"type": "array", "items": ref("File")}
    assert submission["theme"] == {"type": "integer"}
    submission_set = components["SubmissionSet"]["properties"]
    assert list(submission_set) == [
        "id",
        "created",
        "modified",
        "submissions",
        "author",
        "contest",
    ]
    assert submission_set["author"] == ref("Author")
    assert submission_set["submissions"] == {
        "type": "array",
        "items": ref("Submission"),
    }
    for kept in (
        "Author",
        "AuthorRequest",
        "File",
        "PaginatedSubmissionList",
        "PaginatedSubmissionSetList",
    ):
        assert kept in components
    for removed in (
        "SubmissionRequest",
        "PatchedSubmissionRequest",
        "SubmissionWrite",
        "IdRelated",
        "IdRelatedRequest",
        "PatchedAuthorRequest",
        "SubmissionSetRequest",
        "PaginatedAuthorList",
    ):
        assert removed not in components
