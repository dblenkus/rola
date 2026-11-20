"""Register accounts without revealing which addresses already have one."""

import queue
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth.hashers import MD5PasswordHasher
from django.core import mail
from django.core.cache import cache
from django.db import connection, transaction
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework.test import APIClient

from rola.accounts.models import Location, User
from tests.factories import (
    first_link,
    registration,
    wait_until_blocked_by_this_connection,
)


@pytest.mark.parametrize(("length", "status"), [(100, 202), (101, 400)])
def test_registration_validates_address_lengths(db, address, length, status):
    address = dict.fromkeys(address, "x" * length)
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

    assert response.status_code == status
    if status == 202:
        location = User.objects.get().location
        assert {field: getattr(location, field) for field in address} == address
    else:
        assert set(response.data) == set(address)
        assert all(errors[0].code == "max_length" for errors in response.data.values())
        assert not User.objects.exists()
        assert not Location.objects.exists()


def test_registration_validation_does_not_leave_an_address(db, address):
    response = APIClient().post(
        reverse("user-list"),
        {
            "email": "new@example.com",
            "password": "short",
            "first_name": "New",
            "last_name": "Account",
            **address,
        },
        format="json",
    )
    assert response.status_code == 400
    assert set(response.data) == {"password"}
    assert not Location.objects.exists()
    assert not User.objects.exists()


@override_settings(
    AUTH_PASSWORD_VALIDATORS=[
        {
            "NAME": "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        }
    ]
)
def test_registration_password_is_checked_against_submitted_name(db, address):
    response = APIClient().post(
        reverse("user-list"),
        {
            "email": "new@example.com",
            "password": "Original!73",
            "first_name": "Original!73",
            "last_name": "Account",
            **address,
        },
        format="json",
    )

    assert response.status_code == 400
    assert response.data == {
        "password": ["The password is too similar to the first name."]
    }
    assert not User.objects.exists()
    assert not Location.objects.exists()


def link_token(message):
    """Return the token of the first link in a plain-text email body."""
    return parse_qs(urlsplit(first_link(message)).query)["token"][0]


@override_settings(ROLA_FRONTEND_URL="https://photos.example.com/")
@pytest.mark.parametrize(
    "email", ["person@example.com", "person@Example.com", "PERSON@example.com"]
)
def test_registration_of_an_existing_address_answers_like_a_new_one(
    account, address, email, django_capture_on_commit_callbacks
):
    client = APIClient()
    with django_capture_on_commit_callbacks(execute=True):
        existing = client.post(
            reverse("user-list"), registration(email, address), format="json"
        )

    assert existing.status_code == 202
    assert existing.content == b""
    assert User.objects.get() == account
    assert not Location.objects.exists()
    (message,) = mail.outbox
    assert message.to == [account.email]
    assert first_link(message).startswith("https://photos.example.com/password-reset?")
    response = client.post(
        reverse("password-reset-list"),
        {"token": link_token(message), "new_password": "Replacement!73"},
    )
    assert response.status_code == 204
    account.refresh_from_db()
    assert account.check_password("Replacement!73")

    new = client.post(
        reverse("user-list"), registration("new@example.com", address), format="json"
    )
    assert (new.status_code, new.content) == (existing.status_code, existing.content)


def test_registration_of_an_existing_address_attempts_no_insert(account, address):
    encode = MD5PasswordHasher.encode
    hashed = []

    def record(hasher, password, salt):
        hashed.append(password)
        return encode(hasher, password, salt)

    with (
        patch.object(MD5PasswordHasher, "encode", record),
        CaptureQueriesContext(connection) as queries,
    ):
        response = APIClient().post(
            reverse("user-list"),
            registration("PERSON@example.com", address),
            format="json",
        )

    assert response.status_code == 202
    # PostgreSQL logs a failed account insert with its values: the
    # registrant's email, names and password hash.
    tables = ('INSERT INTO "accounts_user"', 'INSERT INTO "accounts_location"')
    assert not [query for query in queries if query["sql"].startswith(tables)]
    # As for a new address, so that the response time is alike.
    assert hashed == ["Original!73"]


@override_settings(ROLA_FRONTEND_URL="https://photos.example.com/")
def test_registration_of_an_inactive_address_sends_a_reset_link_that_activates(
    db, address, django_capture_on_commit_callbacks
):
    # Whoever registered the address first chose this password.
    pending = User.objects.create_user(email="person@example.com", password="Preset!73")
    client = APIClient()
    with django_capture_on_commit_callbacks(execute=True):
        response = client.post(
            reverse("user-list"), registration(pending.email, address), format="json"
        )
    assert response.status_code == 202
    (message,) = mail.outbox
    assert message.to == [pending.email]

    response = client.post(
        reverse("password-reset-list"),
        {"token": link_token(message), "new_password": "Replacement!73"},
    )

    assert response.status_code == 204
    pending.refresh_from_db()
    assert pending.is_active
    assert pending.check_password("Replacement!73")
    login = client.post(
        reverse("token-list"), {"email": pending.email, "password": "Replacement!73"}
    )
    assert login.status_code == 201


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
@override_settings(ROLA_FRONTEND_URL="https://photos.example.com/")
def test_concurrent_registrations_of_one_address_answer_202(address):
    payload = registration("person@example.com", address)
    backend_pids = queue.SimpleQueue()

    def register(remote_addr):
        # Separate client addresses keep the registration throttle's advisory
        # lock out of the way, so the second request meets the account row.
        return APIClient(REMOTE_ADDR=remote_addr).post(
            reverse("user-list"), payload, format="json"
        )

    def register_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return register("198.51.100.2")
        finally:
            connection.close()

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                first = register("198.51.100.1")
                concurrent = executor.submit(register_on_another_connection)
                # The second account insert waits for this uncommitted one.
                wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
            second = concurrent.result(timeout=10)
    finally:
        # Transactional tests flush model tables only, not the registration
        # throttle's history in the cache table.
        cache.clear()

    assert first.status_code == second.status_code == 202
    assert first.content == second.content == b""
    assert User.objects.count() == Location.objects.count() == 1
    assert sorted(urlsplit(first_link(message)).path for message in mail.outbox) == [
        "/password-reset",
        "/register/activate",
    ]
