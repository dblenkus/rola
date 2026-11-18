"""Expire login tokens and keep their keys out of descriptions."""

from datetime import timedelta

from django.urls import reverse
from django.utils.timezone import now
from rest_framework.test import APIClient

from rola.accounts.models import Token


def test_expired_login_tokens_are_rejected(account):
    token = Token.objects.create_token(
        user=account, expires=now() - timedelta(seconds=1)
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
    assert client.get(reverse("user-list")).status_code == 401
    account.is_active = False
    account.save(update_fields=["is_active"])
    token.expires = now() + timedelta(days=1)
    token.save(update_fields=["expires"])
    assert client.get(reverse("user-list")).status_code == 401


def test_token_description_does_not_reveal_its_key(account):
    token = Token.objects.create_token(user=account)
    assert token.key not in str(token)
