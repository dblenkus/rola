"""Serve the five anonymous account operations as resources under ``/api/v1``."""

import pytest
from rest_framework.test import APIClient

from rola.accounts.models import TOKEN_PREFIX, Token, User, token_digest
from rola.accounts.utils.signing import generate_activation_token, generate_reset_token
from tests.factories import client_sending, registration


def log_in(account, address):
    """Ask for a login token with the fixture account's credentials."""
    return "/api/v1/tokens", {"email": account.email, "password": "Original!73"}


def register(account, address):
    """Register a new account."""
    return "/api/v1/users", registration("new@example.com", address)


def activate(account, address):
    """Activate a pending account with its email token."""
    pending = User.objects.create_user(
        email="pending@example.com", password="Original!73"
    )
    return "/api/v1/activations", {"token": generate_activation_token(pending)}


def request_reset(account, address):
    """Ask for a password reset email."""
    return "/api/v1/password-reset-requests", {"email": account.email}


def reset(account, address):
    """Set a new password with a reset token."""
    return "/api/v1/password-resets", {
        "token": generate_reset_token(account),
        "new_password": "Replacement!73",
    }


EMPTY_ANSWERS = [(register, 202), (activate, 204), (request_reset, 202), (reset, 204)]
OPERATIONS = [(log_in, 201), *EMPTY_ANSWERS]


def test_login_answers_201_with_the_token(account, address):
    response = APIClient().post(*log_in(account, address), format="json")

    assert response.status_code == 201
    assert set(response.json()) == {"token", "expires"}
    issued = Token.objects.get(digest=token_digest(response.json()["token"]))
    assert issued.user_id == account.pk


@pytest.mark.parametrize(("operation", "status"), EMPTY_ANSWERS)
def test_operations_without_a_result_answer_with_an_empty_body(
    account, address, operation, status
):
    response = APIClient().post(*operation(account, address), format="json")

    assert response.status_code == status
    assert response.content == b""


@pytest.mark.parametrize(("operation", "status"), OPERATIONS)
def test_a_stale_authorization_header_is_ignored(account, address, operation, status):
    client = client_sending(f"Bearer {TOKEN_PREFIX}not-a-valid-token")

    response = client.post(*operation(account, address), format="json")

    assert response.status_code == status


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/user"),
        ("post", "/api/v1/user"),
        ("post", "/api/v1/user/login"),
        ("post", "/api/v1/user/logout"),
        ("post", "/api/v1/user/activate_account"),
        ("post", "/api/v1/user/request_password_reset"),
        ("post", "/api/v1/user/password_reset"),
        ("get", "/api/v1/user/{id}"),
        ("put", "/api/v1/user/{id}"),
        ("patch", "/api/v1/user/{id}"),
        ("delete", "/api/v1/user/{id}"),
        ("post", "/api/v1/user/{id}/change_password"),
        ("get", "/api/v1/users/{id}"),
        ("patch", "/api/v1/users/{id}"),
        ("delete", "/api/v1/users/{id}"),
    ],
)
def test_removed_account_paths_are_not_served(client, account, method, path):
    response = getattr(client, method)(path.format(id=account.id), {}, format="json")

    assert response.status_code == 404
