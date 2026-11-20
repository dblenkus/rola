"""Log out by deleting the login token that the request presents."""

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.test import APIClient

from rola.accounts.models import Token, User
from tests.factories import bearer_client, mark_account, marked_authors

LOGOUT = "/api/v1/tokens/current"


def expired_tokens():
    """Return the stored tokens that no longer authenticate."""
    return Token.objects.filter(expires__lte=now())


@pytest.fixture
def own_set(account):
    """Mark the fixture account with a submission set that only its tokens list."""
    return mark_account(account)


def test_logout_path_is_the_current_token():
    assert reverse("token-current") == LOGOUT


def test_logout_answers_without_a_body_and_expires_the_token(own_set, client):
    assert marked_authors(client) == ["Own"]

    response = client.delete(LOGOUT)

    assert response.status_code == 204
    assert response.content == b""
    refused = client.get(reverse("submission-list"))
    assert refused.status_code == 401
    assert refused.data == {"detail": "Token has expired"}


def test_logged_out_token_cannot_log_out_again(client):
    assert client.delete(LOGOUT).status_code == 204

    response = client.delete(LOGOUT)

    assert response.status_code == 401
    assert response.data == {"detail": "Token has expired"}


def test_logout_keeps_every_other_token(account, own_set, client):
    same_account = Token.objects.create_token(user=account)
    stranger = User.objects.create_user(
        email="stranger@example.com", password="Original!73", is_active=True
    )
    mark_account(stranger, "Stranger")
    other_account = Token.objects.create_token(user=stranger)

    assert client.delete(LOGOUT).status_code == 204

    assert marked_authors(bearer_client(same_account.key)) == ["Own"]
    assert marked_authors(bearer_client(other_account.key)) == ["Stranger"]
    assert expired_tokens().count() == 1
    for token in (same_account, other_account):
        assert Token.objects.get(pk=token.pk).expires == token.expires


def test_logout_without_credentials_is_refused_and_expires_nothing(own_set, client):
    response = APIClient().delete(LOGOUT)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert not expired_tokens().exists()
    assert marked_authors(client) == ["Own"]


def test_expired_token_cannot_log_out(account):
    token = Token.objects.create_token(user=account, expires=now() - timedelta(hours=1))

    response = bearer_client(token.key).delete(LOGOUT)

    assert response.status_code == 401
    assert response.data == {"detail": "Token has expired"}
    assert Token.objects.get().expires == token.expires


@pytest.mark.parametrize("method", ["get", "put", "patch", "post"])
def test_logout_accepts_only_delete(own_set, client, method):
    response = getattr(client, method)(LOGOUT)

    assert response.status_code == 405
    assert not expired_tokens().exists()
    assert marked_authors(client) == ["Own"]


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/tokens/other",
        "/api/v1/tokens/00000000-0000-0000-0000-000000000000",
        "/api/v1/tokens/1",
    ],
)
def test_no_other_token_can_be_deleted(account, own_set, client, path):
    other = Token.objects.create_token(user=account)

    response = client.delete(path)

    assert response.status_code == 404
    assert not expired_tokens().exists()
    assert marked_authors(bearer_client(other.key)) == ["Own"]
    assert marked_authors(client) == ["Own"]


def test_login_still_ignores_a_logged_out_token(account, client):
    assert client.delete(LOGOUT).status_code == 204

    response = client.post(
        reverse("token-list"),
        {"email": account.email, "password": "Original!73"},
        format="json",
    )

    assert response.status_code == 201
