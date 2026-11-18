"""Limit login, registration, activation and recovery attempts per client."""

import queue
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from django.conf import settings
from django.core.cache import cache
from django.db import connection, transaction
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from rola.accounts.models import User
from rola.accounts.throttling import (
    ActivationThrottle,
    LoginThrottle,
    RecoveryThrottle,
    RegistrationThrottle,
)
from rola.accounts.utils.signing import (
    generate_activation_token,
)
from tests.factories import registration, wait_until_blocked_by_this_connection


def test_login_is_rate_limited(db):
    client = APIClient()
    credentials = {"email": "nobody@example.com", "password": "wrong"}
    with patch.object(LoginThrottle, "rate", "1/hour", create=True):
        assert client.post(reverse("login"), credentials).status_code == 400
        assert client.post(reverse("login"), credentials).status_code == 429


def test_login_limit_survives_a_full_cache(db):
    client = APIClient()
    credentials = {"email": "nobody@example.com", "password": "wrong"}
    with patch.object(LoginThrottle, "rate", "1/hour", create=True):
        assert client.post(reverse("login"), credentials).status_code == 400
        assert client.post(reverse("login"), credentials).status_code == 429
        for i in range(400):
            cache.set(f"throttle_registration_{i}", [time.time()], 3600)
        assert client.post(reverse("login"), credentials).status_code == 429


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Advisory locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_concurrent_checks_for_one_address_share_its_budget(rf):
    request = rf.post(reverse("login"))
    backend_pids = queue.SimpleQueue()

    def check_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return LoginThrottle().allow_request(request, None)
        finally:
            connection.close()

    try:
        with (
            patch.object(LoginThrottle, "rate", "1/minute", create=True),
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            with transaction.atomic():
                assert LoginThrottle().allow_request(request, None)
                check = executor.submit(check_on_another_connection)
                wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
            assert check.result(timeout=10) is False
    finally:
        # Transactional tests flush model tables only, not the cache table.
        cache.clear()


@pytest.mark.parametrize("method", ["get", "post"])
def test_unthrottled_session_login_is_not_served(account, method):
    response = getattr(APIClient(), method)(
        "/api-auth/login/", {"username": account.email, "password": "Original!73"}
    )
    assert response.status_code == 404


def test_registration_and_recovery_have_separate_limits(account, address):
    client = APIClient()
    recovery = {"email": account.email}

    with (
        patch.object(RegistrationThrottle, "rate", "1/hour", create=True),
        patch.object(RecoveryThrottle, "rate", "1/hour", create=True),
    ):
        reset_url = reverse("user-request-password-reset")
        assert client.post(reset_url, recovery).status_code == 200
        assert client.post(reset_url, recovery).status_code == 429
        response = client.post(
            reverse("user-list"),
            registration("first@example.com", address),
            format="json",
        )
        assert response.status_code == 201
        response = client.post(
            reverse("user-list"),
            registration("second@example.com", address),
            format="json",
        )
        assert response.status_code == 429


def test_registration_and_activation_have_separate_limits(db, address):
    User.objects.create_user(email="pending@example.com", password="Original!73")

    def register(client, email):
        return client.post(
            reverse("user-list"), registration(email, address), format="json"
        )

    def activate(client, email):
        token = generate_activation_token(User.objects.get(email=email))
        return client.post(reverse("user-activate-account"), {"token": token})

    with (
        patch.object(RegistrationThrottle, "rate", "1/hour", create=True),
        patch.object(ActivationThrottle, "rate", "1/hour", create=True),
    ):
        # Budgets are per client address, so each direction gets its own.
        client = APIClient(REMOTE_ADDR="198.51.100.1")
        assert register(client, "first@example.com").status_code == 201
        assert register(client, "second@example.com").status_code == 429
        assert activate(client, "first@example.com").status_code == 200

        client = APIClient(REMOTE_ADDR="198.51.100.2")
        assert activate(client, "pending@example.com").status_code == 200
        assert activate(client, "pending@example.com").status_code == 429
        assert register(client, "third@example.com").status_code == 201

    assert User.objects.get(email="first@example.com").is_active
    assert User.objects.get(email="pending@example.com").is_active


def test_password_change_shares_the_login_limit(client, account):
    url = reverse("user-change-password", kwargs={"id": account.id})
    with patch.object(LoginThrottle, "rate", "2/hour", create=True):
        login = APIClient().post(
            reverse("login"), {"email": account.email, "password": "wrong"}
        )
        wrong = client.post(
            url, {"current_password": "wrong", "new_password": "Replacement!73"}
        )
        response = client.post(
            url, {"current_password": "Original!73", "new_password": "Replacement!73"}
        )
    assert login.status_code == 400
    assert wrong.status_code == 400
    assert response.status_code == 429
    assert 0 < int(response.headers["Retry-After"]) <= 3600
    account.refresh_from_db()
    assert account.check_password("Original!73")


@pytest.mark.parametrize(("num_proxies", "second_status"), [(0, 429), (1, 400)])
def test_login_limit_counts_forwarded_clients_only_behind_trusted_proxies(
    db, num_proxies, second_status
):
    client = APIClient()
    credentials = {"email": "nobody@example.com", "password": "wrong"}
    with (
        override_settings(
            REST_FRAMEWORK={**settings.REST_FRAMEWORK, "NUM_PROXIES": num_proxies}
        ),
        patch.object(LoginThrottle, "rate", "1/hour", create=True),
    ):
        first = client.post(
            reverse("login"), credentials, HTTP_X_FORWARDED_FOR="198.51.100.1"
        )
        second = client.post(
            reverse("login"), credentials, HTTP_X_FORWARDED_FOR="198.51.100.2"
        )
    assert first.status_code == 400
    assert second.status_code == second_status
