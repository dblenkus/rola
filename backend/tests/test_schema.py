"""Describe the contest, judging and result endpoints in the API contract."""

import pytest
from django.core.management import call_command
from drf_spectacular.generators import SchemaGenerator


@pytest.fixture(scope="module")
def components():
    """Return the component schemas of the generated API schema."""
    schema = SchemaGenerator().get_schema(request=None, public=True)
    return schema["components"]["schemas"]


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
        "items": {"$ref": "#/components/schemas/SubmissionResults"},
        "readOnly": True,
    }
