"""Log out by expiring the login token that the request presents."""

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.test import APIClient

from rola.accounts.models import Token, User
from tests.factories import bearer_client


def own_accounts(client):
    """List the accounts that the API shows to the client's caller."""
    response = client.get(reverse("user-list"))
    assert response.status_code == 200
    return [result["email"] for result in response.data["results"]]


def expired_tokens():
    """Return the stored tokens that no longer authenticate."""
    return Token.objects.filter(expires__lte=now())


def test_logout_answers_without_a_body_and_expires_the_token(account, client):
    assert own_accounts(client) == [account.email]

    response = client.post(reverse("logout"))

    assert response.status_code == 204
    assert response.content == b""
    refused = client.get(reverse("user-list"))
    assert refused.status_code == 401
    assert refused.data == {"detail": "Token has expired"}


def test_logged_out_token_cannot_log_out_again(client):
    assert client.post(reverse("logout")).status_code == 204

    response = client.post(reverse("logout"))

    assert response.status_code == 401
    assert response.data == {"detail": "Token has expired"}


def test_logout_keeps_every_other_token(account, client):
    same_account = Token.objects.create_token(user=account)
    stranger = User.objects.create_user(
        email="stranger@example.com", password="Original!73", is_active=True
    )
    other_account = Token.objects.create_token(user=stranger)

    assert client.post(reverse("logout")).status_code == 204

    assert own_accounts(bearer_client(same_account.key)) == [account.email]
    assert own_accounts(bearer_client(other_account.key)) == [stranger.email]
    assert expired_tokens().count() == 1
    for token in (same_account, other_account):
        assert Token.objects.get(pk=token.pk).expires == token.expires


def test_logout_without_credentials_is_refused_and_expires_nothing(account, client):
    response = APIClient().post(reverse("logout"))

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert not expired_tokens().exists()
    assert own_accounts(client) == [account.email]


def test_expired_token_cannot_log_out(account):
    token = Token.objects.create_token(user=account, expires=now() - timedelta(hours=1))

    response = bearer_client(token.key).post(reverse("logout"))

    assert response.status_code == 401
    assert response.data == {"detail": "Token has expired"}
    assert Token.objects.get().expires == token.expires


@pytest.mark.parametrize("method", ["get", "put", "patch", "delete"])
def test_logout_accepts_only_post(account, client, method):
    response = getattr(client, method)(reverse("logout"))

    assert response.status_code == 405
    assert not expired_tokens().exists()
    assert own_accounts(client) == [account.email]
