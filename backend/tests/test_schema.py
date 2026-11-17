"""Describe the contest, judging and result endpoints in the API contract."""

import io

import pytest
from django.core.management import call_command
from drf_spectacular.generators import SchemaGenerator
from PIL import Image

from tests.factories import payload


@pytest.fixture(scope="module")
def schema():
    """Generate the API schema the way the offline schema command does."""
    return SchemaGenerator().get_schema(request=None, public=True)


@pytest.fixture(scope="module")
def components(schema):
    """Return the component schemas of the generated API schema."""
    return schema["components"]["schemas"]


def ref(component):
    """Return a reference to a component schema."""
    return {"$ref": f"#/components/schemas/{component}"}


def json_schema(body):
    """Return the JSON schema of a request body or a response."""
    return body["content"]["application/json"]["schema"]


def test_schema_generates_without_warnings(tmp_path):
    call_command(
        "spectacular",
        "--validate",
        "--fail-on-warn",
        "--file",
        str(tmp_path / "openapi.yaml"),
    )


def test_judging_contests_have_their_own_components(components):
    judge_themes = components["JudgeContest"]["properties"]["themes"]
    assert judge_themes["items"] == {"$ref": "#/components/schemas/JudgeTheme"}
    assert "ratings_number" in components["JudgeTheme"]["properties"]
    themes = components["Contest"]["properties"]["themes"]
    assert themes["items"] == {"$ref": "#/components/schemas/Theme"}
    assert "ratings_number" not in components["Theme"]["properties"]


def test_counts_and_acceptance_are_typed(components):
    assert components["Theme"]["properties"]["submissions_number"]["type"] == "integer"
    judge_theme = components["JudgeTheme"]["properties"]
    assert judge_theme["ratings_number"]["type"] == "integer"
    assert judge_theme["submissions_number"]["type"] == "integer"
    assert (
        components["SubmissionResults"]["properties"]["accepted"]["type"] == "boolean"
    )


@pytest.mark.parametrize(
    ("component", "field", "expected"),
    [
        ("Author", "email", {"type": "string", "nullable": True, "readOnly": True}),
        (
            "AuthorResults",
            "country",
            {"type": "string", "nullable": True, "readOnly": True},
        ),
        (
            "AuthorResults",
            "reward",
            {"type": "string", "nullable": True, "readOnly": True},
        ),
        (
            "AuthorResults",
            "reward_theme",
            {"type": "integer", "nullable": True, "readOnly": True},
        ),
        (
            "SubmissionResults",
            "rating",
            {"type": "integer", "nullable": True, "readOnly": True},
        ),
        (
            "SubmissionResults",
            "reward_kind",
            {"type": "string", "nullable": True, "readOnly": True},
        ),
        (
            "SubmissionResults",
            "reward_label",
            {"type": "string", "nullable": True, "readOnly": True},
        ),
        (
            "SubmissionResults",
            "files",
            {
                "type": "array",
                "items": {"$ref": "#/components/schemas/File"},
                "nullable": True,
                "readOnly": True,
            },
        ),
    ],
)
def test_optional_result_fields_are_nullable(components, component, field, expected):
    schema = dict(components[component]["properties"][field])
    schema.pop("description", None)
    assert schema == expected


def test_result_authors_have_only_public_fields(components):
    assert set(components["AuthorResults"]["properties"]) == {
        "id",
        "first_name",
        "last_name",
        "school",
        "club",
        "country",
        "reward",
        "reward_theme",
    }


def test_theme_results_list_submission_results(components):
    assert components["ThemeResults"]["properties"]["submissions"] == {
        "type": "array",
        "items": {"$ref": "#/components/schemas/ThemeSubmissionResults"},
        "readOnly": True,
    }
    theme_rows = components["ThemeSubmissionResults"]["properties"]
    rows = components["SubmissionResults"]["properties"]
    assert "rating" in rows
    assert theme_rows == {name: rows[name] for name in rows if name != "rating"}


@pytest.mark.django_db
def test_submission_writes_respond_with_ids(schema, components, world):
    def one_or_many(component):
        return {"oneOf": [ref(component), {"type": "array", "items": ref(component)}]}

    create = schema["paths"]["/api/v1/submission"]["post"]
    assert json_schema(create["responses"]["201"]) == one_or_many("SubmissionWrite")
    assert json_schema(create["requestBody"]) == one_or_many("SubmissionRequest")
    for method in ("put", "patch"):
        update = schema["paths"]["/api/v1/submission/{id}"][method]
        assert json_schema(update["responses"]["200"]) == ref("SubmissionWrite")
    write = components["SubmissionWrite"]["properties"]
    assert write["author"] == ref("IdRelated")
    assert write["files"] == {"type": "array", "items": ref("IdRelated")}

    data = payload(world)
    created = world.client.post("/api/v1/submission", data, format="json")
    assert created.status_code == 201
    assert set(created.data) == set(write)
    assert created.data["author"] == {"id": world.author.pk}
    assert created.data["files"] == data["files"]
    batch = world.client.post("/api/v1/submission", [payload(world)], format="json")
    assert batch.status_code == 201
    assert [set(item) for item in batch.data] == [set(write)]
    patched = world.client.patch(
        f"/api/v1/submission/{created.data['id']}", {"title": "New"}, format="json"
    )
    assert patched.status_code == 200
    assert set(patched.data) == set(write)
    assert patched.data["author"] == {"id": world.author.pk}


@pytest.mark.django_db
def test_photograph_upload_takes_a_jpeg_body(schema, world):
    upload = schema["paths"]["/api/v1/file"]["post"]
    assert upload["requestBody"]["content"] == {
        "image/jpeg": {"schema": {"type": "string", "format": "binary"}}
    }
    [disposition] = [
        parameter
        for parameter in upload["parameters"]
        if parameter["name"] == "Content-Disposition"
    ]
    assert disposition["in"] == "header"
    assert disposition["required"] is True
    assert json_schema(upload["responses"]["201"]) == ref("File")

    jpeg = io.BytesIO()
    Image.new("RGB", (100, 100)).save(jpeg, "JPEG")
    unnamed = world.client.post(
        "/api/v1/file", jpeg.getvalue(), content_type="image/jpeg"
    )
    assert unnamed.status_code == 400
    named = world.client.post(
        "/api/v1/file",
        jpeg.getvalue(),
        content_type="image/jpeg",
        headers={"Content-Disposition": 'attachment; filename="photo.jpg"'},
    )
    assert named.status_code == 201
