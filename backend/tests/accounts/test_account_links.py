"""Send activation and recovery links that redeem once and reveal no accounts."""

import queue
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import pytest
from django.core import mail, signing
from django.db import connection, transaction
from django.test import override_settings
from django.urls import reverse
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient

from rola.accounts.models import User
from rola.accounts.serializers import (
    ActivationSerializer,
    PasswordResetSerializer,
)
from rola.accounts.utils.signing import (
    PASSWORD_RESET_SALT,
    USER_ACTIVATION_SALT,
    generate_activation_token,
    generate_reset_token,
)
from tests.factories import first_link, wait_until_blocked_by_this_connection


@override_settings(ROLA_FRONTEND_URL="https://photos.example.com/")
def test_activation_email_links_to_the_configured_frontend(
    db, address, django_capture_on_commit_callbacks
):
    with django_capture_on_commit_callbacks(execute=True):
        response = APIClient().post(
            reverse("user-list"),
            {
                "email": "new@example.com",
                "password": "Original!73",
                "first_name": "New",
                "last_name": "Account",
                **address,
            },
            format="json",
        )
    assert response.status_code == 201
    link = first_link(mail.outbox[0])
    assert link.startswith("https://photos.example.com/register/activate?")
    assert parse_qs(urlsplit(link).query)["token"]


@override_settings(ROLA_FRONTEND_URL="https://photos.example.com/")
def test_recovery_email_links_to_the_configured_frontend(
    account, django_capture_on_commit_callbacks
):
    with django_capture_on_commit_callbacks(execute=True):
        response = APIClient().post(
            reverse("user-request-password-reset"), {"email": account.email}
        )
    assert response.status_code == 200
    link = first_link(mail.outbox[0])
    assert link.startswith("https://photos.example.com/password-reset?")
    assert parse_qs(urlsplit(link).query)["token"]


def test_activation_link_can_be_opened_again(db):
    user = User.objects.create_user(email="person@example.com", password="Original!73")
    payload = {"token": generate_activation_token(user)}
    client = APIClient()

    first = client.post(reverse("user-activate-account"), payload)
    second = client.post(reverse("user-activate-account"), payload)

    assert first.status_code == second.status_code == 200
    user.refresh_from_db()
    assert user.is_active


def test_validated_recovery_token_cannot_be_replayed(account):
    data = {"token": generate_reset_token(account), "new_password": "Replacement!73"}
    first = PasswordResetSerializer(data=data)
    second = PasswordResetSerializer(data=data)
    first.is_valid(raise_exception=True)
    second.is_valid(raise_exception=True)
    first.save()

    with pytest.raises(ValidationError, match="Bad token"):
        second.save()
    account.refresh_from_db()
    assert account.check_password("Replacement!73")


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_concurrent_token_redemptions_succeed_once():
    user = User.objects.create_user(
        email="person@example.com", password="Original!73", is_active=True
    )
    data = {"token": generate_reset_token(user), "new_password": "Replacement!73"}
    first = PasswordResetSerializer(data=data)
    second = PasswordResetSerializer(data=data)
    first.is_valid(raise_exception=True)
    second.is_valid(raise_exception=True)
    backend_pids = queue.SimpleQueue()

    def redeem_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return second.save()
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            first.save()
            redemption = executor.submit(redeem_on_another_connection)
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        with pytest.raises(ValidationError, match="Bad token"):
            redemption.result(timeout=10)

    user.refresh_from_db()
    assert user.is_active
    assert user.password_reset_counter == 1


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_concurrent_activations_both_succeed():
    user = User.objects.create_user(email="person@example.com", password="Original!73")
    data = {"token": generate_activation_token(user)}
    first = ActivationSerializer(data=data)
    second = ActivationSerializer(data=data)
    first.is_valid(raise_exception=True)
    second.is_valid(raise_exception=True)
    backend_pids = queue.SimpleQueue()

    def activate_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return second.save()
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            first.save()
            activation = executor.submit(activate_on_another_connection)
            # The second activation waits for the first one's row lock and then
            # finds the account already active.
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        assert activation.result(timeout=10) == user

    user.refresh_from_db()
    assert user.is_active


def test_recovery_does_not_reveal_unknown_or_inactive_accounts(
    account, django_capture_on_commit_callbacks
):
    client = APIClient()
    with django_capture_on_commit_callbacks(execute=True):
        active = client.post(
            reverse("user-request-password-reset"), {"email": account.email}
        )
        unknown = client.post(
            reverse("user-request-password-reset"), {"email": "unknown@example.com"}
        )
        account.is_active = False
        account.save(update_fields=["is_active"])
        inactive = client.post(
            reverse("user-request-password-reset"), {"email": account.email}
        )
    assert active.status_code == unknown.status_code == inactive.status_code == 200
    assert active.data == unknown.data == inactive.data
    assert len(mail.outbox) == 1


@pytest.mark.parametrize(
    "payload", [None, {}, {"email": [], "counter": 0}, {"email": "x", "counter": True}]
)
def test_signed_malformed_recovery_payload_returns_validation_error(db, payload):
    response = APIClient().post(
        reverse("user-password-reset"),
        {
            "token": signing.dumps(payload, salt=PASSWORD_RESET_SALT),
            "new_password": "Replacement!73",
        },
    )
    assert response.status_code == 400


@pytest.mark.parametrize("payload", [None, {"email": "person@example.com"}, ["x"]])
def test_signed_malformed_activation_payload_returns_validation_error(db, payload):
    response = APIClient().post(
        reverse("user-activate-account"),
        {"token": signing.dumps(payload, salt=USER_ACTIVATION_SALT)},
    )
    assert response.status_code == 400
