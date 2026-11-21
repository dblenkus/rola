"""Describe the contest, judging and result endpoints in the API contract."""

import io

import pytest
from django.core.management import call_command
from drf_spectacular.generators import SchemaGenerator
from PIL import Image


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


def test_institution_kinds_have_a_named_enum(components):
    kind = components["Institution"]["properties"]["kind"]
    assert kind["allOf"] == [ref("InstitutionKindEnum")]
    assert components["InstitutionKindEnum"]["enum"] == [1]
    assert "KindEnum" not in components


def test_judging_contests_have_their_own_components(components):
    judge_themes = components["JudgeContest"]["properties"]["themes"]
    assert judge_themes["items"] == {"$ref": "#/components/schemas/JudgeTheme"}
    assert "rating_count" in components["JudgeTheme"]["properties"]
    themes = components["Contest"]["properties"]["themes"]
    assert themes["items"] == {"$ref": "#/components/schemas/Theme"}
    assert "rating_count" not in components["Theme"]["properties"]


def test_counts_and_acceptance_are_typed(components):
    assert components["Theme"]["properties"]["submission_count"]["type"] == "integer"
    judge_theme = components["JudgeTheme"]["properties"]
    assert judge_theme["rating_count"]["type"] == "integer"
    assert judge_theme["submission_count"]["type"] == "integer"
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
            "score",
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


@pytest.mark.django_db
def test_photograph_upload_takes_a_jpeg_body(schema, world):
    upload = schema["paths"]["/api/v1/files"]["post"]
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
        "/api/v1/files", jpeg.getvalue(), content_type="image/jpeg"
    )
    assert unnamed.status_code == 400
    named = world.client.post(
        "/api/v1/files",
        jpeg.getvalue(),
        content_type="image/jpeg",
        headers={"Content-Disposition": 'attachment; filename="photo.jpg"'},
    )
    assert named.status_code == 201
