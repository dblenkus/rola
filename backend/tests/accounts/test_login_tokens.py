"""Issue, store and accept login tokens."""

import re
from datetime import timedelta

import pytest
from django.db import IntegrityError, connection, transaction
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.test import APIClient

from rola.accounts.api.serializers import TokenSerializer
from rola.accounts.models import TOKEN_PREFIX, Token, token_digest
from tests.factories import bearer_client, client_sending


def log_in():
    """Return the token that a login of the fixture account answers with."""
    response = APIClient().post(
        reverse("token-list"),
        {"email": "person@example.com", "password": "Original!73"},
    )
    assert response.status_code == 201
    return response.data["token"]


def create_contest(client):
    """Call an endpoint that answers 401 to a caller who is not logged in."""
    return client.post(reverse("contest-list"))


def test_expired_login_tokens_are_rejected(account):
    token = Token.objects.create_token(
        user=account, expires=now() - timedelta(seconds=1)
    )
    client = bearer_client(token.key)
    assert client.get(reverse("submission-list")).status_code == 401
    account.is_active = False
    account.save(update_fields=["is_active"])
    token.expires = now() + timedelta(days=1)
    token.save(update_fields=["expires"])
    assert client.get(reverse("submission-list")).status_code == 401


def test_token_description_does_not_reveal_its_key(account):
    token = Token.objects.create_token(user=account)
    assert token.key not in str(token)


def test_login_token_is_the_prefix_and_64_hexadecimal_digits(account):
    assert TOKEN_PREFIX == "rola_st_"
    assert re.fullmatch(r"rola_st_[0-9a-f]{64}", log_in())


def test_token_digest_is_sha256():
    # The test vector of FIPS 180-2 for the message "abc".
    assert token_digest("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_token_table_does_not_hold_the_login_token(account):
    secret = log_in().removeprefix(TOKEN_PREFIX)

    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM accounts_token")
        rows = cursor.fetchall()

    assert len(rows) == 1
    assert not [value for value in rows[0] if secret in str(value)]
    assert token_digest(TOKEN_PREFIX + secret) in rows[0]


def test_stored_token_has_no_key(account):
    Token.objects.create_token(user=account)

    with pytest.raises(ValueError, match="only its digest is kept"):
        Token.objects.get().key  # noqa: B018


def test_serializing_a_stored_token_fails_instead_of_omitting_it(account):
    issued = Token.objects.create_token(user=account)

    assert TokenSerializer(issued).data == {
        "token": issued.key,
        "expires": issued.expires.isoformat().replace("+00:00", "Z"),
    }
    with pytest.raises(ValueError, match="only its digest is kept"):
        TokenSerializer(Token.objects.get()).data  # noqa: B018


def test_token_without_a_digest_cannot_be_stored(account):
    with pytest.raises(IntegrityError), transaction.atomic():
        Token.objects.create(user=account, expires=now() + timedelta(days=1))

    assert not Token.objects.exists()


def test_stored_digest_is_not_a_credential(account):
    token = Token.objects.create_token(user=account)
    client = client_sending(f"Bearer {TOKEN_PREFIX}{token.digest}")

    assert client.get(reverse("submission-list")).status_code == 401


def test_token_without_the_prefix_is_refused_without_a_query(
    account, django_assert_num_queries
):
    token = Token.objects.create_token(user=account)
    client = client_sending(f"Bearer {token.key.removeprefix(TOKEN_PREFIX)}")

    with django_assert_num_queries(0):
        response = client.get(reverse("submission-list"))

    assert response.status_code == 401
    assert response.data == {"detail": "Invalid token"}


def test_token_keyword_is_treated_as_anonymous(account):
    token = Token.objects.create_token(user=account)
    client = client_sending(f"Token {token.key}")

    listing = client.get(reverse("contest-list"))

    assert listing.status_code == 200
    assert listing.data["results"] == []
    assert create_contest(client).status_code == 401


@pytest.mark.parametrize("authorization", [None, f"Bearer {TOKEN_PREFIX}unknown"])
def test_refused_calls_ask_for_a_bearer_token(account, authorization):
    client = client_sending(authorization) if authorization else APIClient()

    response = create_contest(client)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
