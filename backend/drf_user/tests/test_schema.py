"""Describe the account endpoints in the generated API contract."""

import pytest
from django.test import Client
from drf_spectacular.generators import SchemaGenerator


@pytest.fixture(scope="module")
def schema():
    """Generate the API schema the way the offline schema command does."""
    return SchemaGenerator().get_schema(request=None, public=True)


@pytest.fixture
def paths(schema):
    """Return the operations of the generated schema by path."""
    return schema["paths"]


def test_token_authentication_is_described_as_an_authorization_header(schema):
    assert schema["components"]["securitySchemes"]["tokenAuth"] == {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization",
        "description": "Use the value Token followed by a space and the login token.",
    }


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/user",
        "/api/v1/user/login",
        "/api/v1/user/activate_account",
        "/api/v1/user/request_password_reset",
        "/api/v1/user/password_reset",
    ],
)
def test_registration_login_and_recovery_are_anonymous(paths, path):
    assert paths[path]["post"]["security"] == [{}]


def test_profile_endpoints_require_a_token(paths):
    profile = paths["/api/v1/user/{id}"]
    for method in ("get", "put", "patch", "delete"):
        assert profile[method]["security"] == [{"tokenAuth": []}]
    change_password = paths["/api/v1/user/{id}/change_password"]["post"]
    assert change_password["security"] == [{"tokenAuth": []}]


def test_registration_responds_without_a_body(paths):
    assert "content" not in paths["/api/v1/user"]["post"]["responses"]["201"]


def test_account_writes_respond_with_the_profile(paths):
    profile = {"$ref": "#/components/schemas/User"}
    for method in ("put", "patch"):
        response = paths["/api/v1/user/{id}"][method]["responses"]["200"]
        assert response["content"]["application/json"]["schema"] == profile
    login = paths["/api/v1/user/login"]["post"]["responses"]["200"]
    assert login["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/Token"
    }


def test_current_account_filter_is_described_as_a_presence_flag(paths):
    assert {
        "in": "query",
        "name": "current",
        "schema": {"type": "string"},
        "description": "Any non-empty value limits the list to the caller's own account.",
    } in paths["/api/v1/user"]["get"]["parameters"]


@pytest.mark.django_db
@pytest.mark.parametrize("path", ["/api/v1/schema/", "/api/v1/docs/"])
def test_schema_and_swagger_are_not_served_at_runtime(path):
    assert Client().get(path).status_code == 404
