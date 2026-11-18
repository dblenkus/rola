"""Keep password changes, resets and hash upgrades consistent with logins."""

import queue
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import MD5PasswordHasher
from django.core.cache import cache
from django.db import connection, transaction
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from rola.accounts.models import Token, User
from rola.accounts.serializers import (
    ChangePasswordSerializer,
    PasswordResetSerializer,
)
from rola.accounts.utils.signing import (
    generate_reset_token,
)
from rola.accounts.views import UserViewSet
from tests.factories import wait_until_blocked_by_this_connection


def test_password_change_revokes_login_and_recovery_tokens(client, account):
    reset_token = generate_reset_token(account)
    response = client.post(
        reverse("user-change-password", kwargs={"id": account.id}),
        {"current_password": "Original!73", "new_password": "Replacement!73"},
    )
    assert response.status_code == 200
    assert all(token.is_expired for token in account.auth_tokens.all())
    assert client.get(reverse("user-list")).status_code == 401
    response = APIClient().post(
        reverse("user-password-reset"),
        {"token": reset_token, "new_password": "Another!73"},
    )
    assert response.status_code == 400


def test_password_reset_revokes_login_tokens(client, account):
    response = APIClient().post(
        reverse("user-password-reset"),
        {"token": generate_reset_token(account), "new_password": "Replacement!73"},
    )
    assert response.status_code == 200
    assert all(token.is_expired for token in account.auth_tokens.all())
    assert client.get(reverse("user-list")).status_code == 401


def replace_password(user, flow):
    """Replace ``Original!73`` with ``Replacement!73`` through ``flow``'s serializer."""
    if flow == "password-change":
        serializer = ChangePasswordSerializer(
            data={"current_password": "Original!73", "new_password": "Replacement!73"},
            context={"user": user},
        )
    else:
        serializer = PasswordResetSerializer(
            data={"token": generate_reset_token(user), "new_password": "Replacement!73"}
        )
    serializer.is_valid(raise_exception=True)
    serializer.save()


@pytest.mark.parametrize("flow", ["password-change", "password-reset"])
def test_profile_update_keeps_a_concurrent_password_change(client, account, flow):
    load_profile = UserViewSet.get_object

    def load_profile_then_replace_password(view):
        profile = load_profile(view)
        replace_password(User.objects.get(pk=profile.pk), flow)
        return profile

    with patch.object(UserViewSet, "get_object", load_profile_then_replace_password):
        response = client.patch(
            reverse("user-detail", kwargs={"id": account.id}), {"first_name": "Changed"}
        )

    assert response.status_code == 200
    account.refresh_from_db()
    assert account.first_name == "Changed"
    assert account.check_password("Replacement!73")
    assert account.password_reset_counter == 1


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("flow", ["password-change", "password-reset"])
def test_profile_update_waiting_on_a_password_change_keeps_it(flow):
    user = User.objects.create_user(
        email="person@example.com", password="Original!73", is_active=True
    )
    client = APIClient()
    client.credentials(
        HTTP_AUTHORIZATION=f"Token {Token.objects.create_token(user=user).key}"
    )
    backend_pids = queue.SimpleQueue()

    def update_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return client.patch(
                reverse("user-detail", kwargs={"id": user.id}),
                {"first_name": "Changed"},
            )
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            replace_password(user, flow)
            update = executor.submit(update_on_another_connection)
            # The update has read the old row and now waits to write it.
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        response = update.result(timeout=10)

    assert response.status_code == 200
    user.refresh_from_db()
    assert user.first_name == "Changed"
    assert user.check_password("Replacement!73")
    assert user.password_reset_counter == 1


@pytest.mark.parametrize("flow", ["password-change", "password-reset"])
def test_login_refuses_a_password_changed_after_the_credential_check(account, flow):
    def authenticate_then_replace_password(**credentials):
        user = authenticate(**credentials)
        replace_password(User.objects.get(pk=user.pk), flow)
        return user

    with patch(
        "rola.accounts.serializers.authenticate", authenticate_then_replace_password
    ):
        response = APIClient().post(
            reverse("login"), {"email": account.email, "password": "Original!73"}
        )

    assert response.status_code == 400
    assert response.json() == {
        "non_field_errors": ["Unable to log in with provided credentials."]
    }
    assert not Token.objects.filter(user=account).exists()
    account.refresh_from_db()
    assert account.check_password("Replacement!73")


@pytest.fixture
def outdated_hash(account):
    """Prefer another hasher than the one that stored the account's password."""
    with override_settings(
        PASSWORD_HASHERS=[
            "django.contrib.auth.hashers.ScryptPasswordHasher",
            *settings.PASSWORD_HASHERS,
        ]
    ):
        yield


def test_login_upgrades_an_outdated_password_hash(account, outdated_hash):
    response = APIClient().post(
        reverse("login"), {"email": account.email, "password": "Original!73"}
    )

    assert response.status_code == 200
    assert Token.objects.get(key=response.data["token"]).user_id == account.pk
    account.refresh_from_db()
    assert account.password.startswith("scrypt$")
    assert account.check_password("Original!73")


def test_login_rehash_keeps_a_concurrent_reset(account, outdated_hash):
    verify = MD5PasswordHasher.verify

    def verify_then_reset(hasher, password, encoded):
        is_correct = verify(hasher, password, encoded)
        replace_password(User.objects.get(pk=account.pk), "password-reset")
        return is_correct

    with patch.object(MD5PasswordHasher, "verify", verify_then_reset):
        response = APIClient().post(
            reverse("login"), {"email": account.email, "password": "Original!73"}
        )

    account.refresh_from_db()
    assert account.check_password("Replacement!73")
    assert not account.check_password("Original!73")
    assert account.password_reset_counter == 1
    assert response.status_code == 400
    assert not Token.objects.filter(user=account).exists()


def test_overlapping_logins_both_upgrade_an_outdated_hash(account, outdated_hash):
    verify = MD5PasswordHasher.verify
    other_logins = []

    def log_in():
        return APIClient().post(
            reverse("login"), {"email": account.email, "password": "Original!73"}
        )

    def verify_then_log_in_again(hasher, password, encoded):
        is_correct = verify(hasher, password, encoded)
        # The other login upgrades the hash before this one stores its own.
        with patch.object(MD5PasswordHasher, "verify", verify):
            other_logins.append(log_in())
        return is_correct

    with patch.object(MD5PasswordHasher, "verify", verify_then_log_in_again):
        response = log_in()

    assert [other.status_code for other in other_logins] == [200]
    assert response.status_code == 200
    assert Token.objects.get(key=response.data["token"]).user_id == account.pk
    account.refresh_from_db()
    assert account.password.startswith("scrypt$")
    assert account.check_password("Original!73")


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_login_waiting_on_a_reset_gets_no_token():
    user = User.objects.create_user(
        email="person@example.com", password="Original!73", is_active=True
    )
    backend_pids = queue.SimpleQueue()

    def log_in_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return APIClient().post(
                reverse("login"), {"email": user.email, "password": "Original!73"}
            )
        finally:
            connection.close()

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                replace_password(user, "password-reset")
                login = executor.submit(log_in_on_another_connection)
                # The login has checked the old password and now waits for the row.
                wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
            response = login.result(timeout=10)
    finally:
        # Transactional tests flush model tables only, not the login throttle's
        # history in the cache table.
        cache.clear()

    assert response.status_code == 400
    assert not Token.objects.filter(user=user).exists()
