"""Describe the account endpoints in the generated API contract."""

import re

import pytest
from django.test import Client
from django.urls import resolve
from drf_spectacular.generators import SchemaGenerator


@pytest.fixture(scope="module")
def schema():
    """Generate the API schema the way the offline schema command does."""
    return SchemaGenerator().get_schema(request=None, public=True)


@pytest.fixture
def paths(schema):
    """Return the operations of the generated schema by path."""
    return schema["paths"]


def account_operations(paths):
    """Return the operations, by path and method, that the accounts app serves."""
    operations = {}
    for path, methods in paths.items():
        # An integer id matches the lookup pattern of every route.
        url = re.sub(r"\{[^}]+\}", "1", path)
        if resolve(url).func.cls.__module__.startswith("rola.accounts."):
            for method, operation in methods.items():
                operations[path, method] = operation
    return operations


def test_token_authentication_is_described_as_a_bearer_token(schema):
    assert schema["components"]["securitySchemes"] == {
        "tokenAuth": {"type": "http", "scheme": "bearer"}
    }


def test_account_operations_are_the_five_anonymous_ones_and_the_logout(paths):
    operations = account_operations(paths)
    logout = operations.pop(("/api/v1/tokens/current", "delete"))

    assert set(operations) == {
        ("/api/v1/tokens", "post"),
        ("/api/v1/users", "post"),
        ("/api/v1/activations", "post"),
        ("/api/v1/password-reset-requests", "post"),
        ("/api/v1/password-resets", "post"),
    }
    assert all(operation["security"] == [{}] for operation in operations.values())
    assert logout["security"] == [{"tokenAuth": []}]


@pytest.mark.parametrize(
    ("path", "request_component"),
    [
        ("/api/v1/tokens", "LoginRequest"),
        ("/api/v1/users", "UserRequest"),
        ("/api/v1/activations", "ActivationRequest"),
        ("/api/v1/password-reset-requests", "RequestPasswordResetRequest"),
        ("/api/v1/password-resets", "PasswordResetRequest"),
    ],
)
def test_account_requests_keep_their_component_names(
    schema, paths, path, request_component
):
    body = paths[path]["post"]["requestBody"]
    assert body["content"]["application/json"]["schema"] == {
        "$ref": f"#/components/schemas/{request_component}"
    }
    assert request_component in schema["components"]["schemas"]


def test_logout_requires_a_token_and_exchanges_no_body(paths):
    assert list(paths["/api/v1/tokens/current"]) == ["delete"]
    logout = paths["/api/v1/tokens/current"]["delete"]
    assert logout["security"] == [{"tokenAuth": []}]
    assert "requestBody" not in logout
    assert list(logout["responses"]) == ["204"]
    assert "content" not in logout["responses"]["204"]


def test_login_responds_with_the_token(schema, paths):
    response = paths["/api/v1/tokens"]["post"]["responses"]
    assert set(response) == {"201"}
    assert response["201"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/Token"
    }
    assert set(schema["components"]["schemas"]["Token"]["properties"]) == {
        "token",
        "expires",
    }


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/api/v1/users", "202"),
        ("/api/v1/activations", "204"),
        ("/api/v1/password-reset-requests", "202"),
        ("/api/v1/password-resets", "204"),
    ],
)
def test_account_operations_without_a_result_respond_without_a_body(
    paths, path, status
):
    responses = paths[path]["post"]["responses"]
    assert set(responses) == {status}
    assert "content" not in responses[status]


@pytest.mark.django_db
@pytest.mark.parametrize("path", ["/api/v1/schema/", "/api/v1/docs/"])
def test_schema_and_swagger_are_not_served_at_runtime(path):
    assert Client().get(path).status_code == 404
