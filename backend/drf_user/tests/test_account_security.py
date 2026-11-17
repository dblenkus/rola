"""Exercise credential and account isolation boundaries."""

import queue
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import MD5PasswordHasher
from django.core import mail, signing
from django.core.cache import cache
from django.db import IntegrityError, connection, transaction
from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient

from drf_user.models import Location, Token, User
from drf_user.serializers import (
    ActivationSerializer,
    ChangePasswordSerializer,
    PasswordResetSerializer,
)
from drf_user.throttling import (
    ActivationThrottle,
    LoginThrottle,
    RecoveryThrottle,
    RegistrationThrottle,
)
from drf_user.utils.signing import (
    PASSWORD_RESET_SALT,
    USER_ACTIVATION_SALT,
    generate_activation_token,
    generate_reset_token,
)
from drf_user.views import UserViewSet


@pytest.fixture
def account(db):
    """Create an active account with an independent login credential."""
    return User.objects.create_user(
        email="person@example.com", password="Original!73", is_active=True
    )


@pytest.fixture
def client(account):
    """Authenticate API calls as the fixture account."""
    client = APIClient()
    client.credentials(
        HTTP_AUTHORIZATION=f"Token {Token.objects.create_token(user=account).key}"
    )
    return client


@pytest.fixture
def address():
    """Provide a complete postal address for account writes."""
    return {
        "address": "Street 1",
        "city": "Ljubljana",
        "postal_code": "1000",
        "country": "SI",
    }


@pytest.mark.parametrize("method", ["put", "patch"])
def test_profile_password_write_is_rejected(client, account, address, method):
    response = getattr(client, method)(
        reverse("user-detail", kwargs={"id": account.id}),
        {
            "password": "Replacement!73",
            "first_name": "Changed",
            "last_name": "Account",
            **address,
        },
        format="json",
    )
    assert response.status_code == 400
    assert set(response.data) == {"password"}
    account.refresh_from_db()
    assert account.check_password("Original!73")
    assert account.first_name is None
    assert not Location.objects.exists()


def test_profile_of_another_account_cannot_be_changed(client, account):
    other = User.objects.create_user(
        email="other@example.com", password="Original!73", is_active=True
    )
    response = client.patch(
        reverse("user-detail", kwargs={"id": other.id}), {"first_name": "Changed"}
    )
    assert response.status_code == 404
    other.refresh_from_db()
    assert other.first_name is None


def test_location_creation_and_partial_update_are_atomic(client, account, address):
    url = reverse("user-detail", kwargs={"id": account.id})
    response = client.get(url)
    assert response.status_code == 200
    assert {field: response.data[field] for field in address} == dict.fromkeys(address)
    assert "location" not in response.data

    response = client.patch(url, {"first_name": "Initial"})
    assert response.status_code == 200
    assert {field: response.data[field] for field in address} == dict.fromkeys(address)
    assert not Location.objects.exists()

    response = client.patch(url, {"city": "Ljubljana"})
    assert response.status_code == 400
    assert set(response.data) == {"address", "postal_code", "country"}
    assert Location.objects.count() == 0
    response = client.patch(url, address)
    assert response.status_code == 200
    assert {field: response.data[field] for field in address} == address
    response = client.patch(url, {"city": "Maribor", "first_name": "Changed"})
    assert response.status_code == 200
    updated_address = {**address, "city": "Maribor"}
    assert {field: response.data[field] for field in address} == updated_address
    account.refresh_from_db()
    assert {
        field: getattr(account.location, field) for field in address
    } == updated_address
    assert account.first_name == "Changed"
    assert Location.objects.count() == 1


@pytest.mark.parametrize("field", ["address", "city", "postal_code", "country"])
@pytest.mark.parametrize(
    ("value", "code"),
    [("x" * 101, "max_length"), (None, "null")],
    ids=["too_long", "null"],
)
def test_invalid_address_field_does_not_update_profile(
    client, account, address, field, value, code
):
    account.location = Location.objects.create(**address)
    account.save(update_fields=["location"])

    response = client.patch(
        reverse("user-detail", kwargs={"id": account.id}),
        {field: value, "first_name": "Changed"},
        format="json",
    )

    assert response.status_code == 400
    assert set(response.data) == {field}
    assert response.data[field][0].code == code
    account.refresh_from_db()
    assert account.first_name is None
    assert {field: getattr(account.location, field) for field in address} == address
    assert Location.objects.count() == 1


@pytest.mark.parametrize(("length", "status"), [(100, 201), (101, 400)])
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
    if status == 201:
        assert {field: response.data[field] for field in address} == address
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


def first_link(message):
    """Return the first HTTPS link in a plain-text email body."""
    return next(
        line for line in message.body.splitlines() if line.startswith("https://")
    )


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


def test_nullable_names_and_user_clean_are_safe(account):
    account.first_name = None
    account.last_name = None
    account.clean()
    assert account.get_full_name() == ""
    assert account.get_short_name() == ""


def test_malformed_account_id_does_not_reach_uuid_lookup(client):
    response = client.get("/api/v1/user/------------------------------------")
    assert response.status_code == 404


@pytest.mark.parametrize(
    "email", ["person@example.com", "person@Example.com", "PERSON@example.com"]
)
def test_registration_rejects_normalized_duplicate_email(account, address, email):
    response = APIClient().post(
        reverse("user-list"),
        {
            "email": email,
            "password": "Original!73",
            "first_name": "New",
            "last_name": "Account",
            **address,
        },
        format="json",
    )
    assert response.status_code == 400
    assert response.data == {"email": ["user with this email already exists."]}
    assert User.objects.count() == 1
    assert not Location.objects.exists()


def test_profile_put_does_not_require_credentials(client, account, address):
    response = client.put(
        reverse("user-detail", kwargs={"id": account.id}),
        {"first_name": "Updated", "last_name": "Account", **address},
        format="json",
    )
    assert response.status_code == 200
    account.refresh_from_db()
    assert account.first_name == "Updated"
    assert account.location.city == address["city"]
    assert account.email == "person@example.com"
    assert account.check_password("Original!73")


@pytest.mark.parametrize("method", ["put", "patch"])
def test_profile_rejects_email_changes_atomically(client, account, address, method):
    response = getattr(client, method)(
        reverse("user-detail", kwargs={"id": account.id}),
        {
            "email": "changed@example.com",
            "first_name": "Changed",
            "last_name": "Account",
            **address,
        },
        format="json",
    )
    assert response.status_code == 400
    assert set(response.data) == {"email"}
    account.refresh_from_db()
    assert account.email == "person@example.com"
    assert account.first_name is None
    assert not Location.objects.exists()


def test_profile_accepts_unchanged_normalized_email(client, account):
    response = client.patch(
        reverse("user-detail", kwargs={"id": account.id}),
        {"email": "Person@Example.com", "first_name": "Updated"},
    )
    assert response.status_code == 200
    account.refresh_from_db()
    assert account.email == "person@example.com"
    assert account.first_name == "Updated"


@pytest.mark.parametrize("stored_email", ["person@example.com", "Person@Example.com"])
def test_registration_checks_uniqueness_against_stored_case(
    account, address, stored_email
):
    User.objects.filter(pk=account.pk).update(email=stored_email)
    response = APIClient().post(
        reverse("user-list"),
        {
            "email": "PERSON@EXAMPLE.COM",
            "password": "Original!73",
            "first_name": "New",
            "last_name": "Account",
            **address,
        },
        format="json",
    )
    assert response.status_code == 400
    assert response.data == {"email": ["user with this email already exists."]}
    assert User.objects.count() == 1
    assert not Location.objects.exists()


def test_database_rejects_addresses_that_differ_only_in_case(account):
    with (
        pytest.raises(IntegrityError, match="drf_user_email_ci_unique"),
        transaction.atomic(),
    ):
        User.objects.bulk_create([User(email="Person@Example.com")])
    assert User.objects.get().email == "person@example.com"


def test_registration_lowercases_email_without_removing_dots_or_tags(db, address):
    response = APIClient().post(
        reverse("user-list"),
        {
            "email": "Person.Name+Contest@Example.com",
            "password": "Original!73",
            "first_name": "New",
            "last_name": "Account",
            **address,
        },
        format="json",
    )
    assert response.status_code == 201
    assert response.data["email"] == "person.name+contest@example.com"
    assert User.objects.get().email == "person.name+contest@example.com"


@pytest.mark.parametrize("method", ["create_user", "create_superuser"])
def test_account_manager_normalizes_email(db, method):
    user = getattr(User.objects, method)(
        email="Person.Name+Contest@Example.com", password="Original!73"
    )
    user.refresh_from_db()
    assert user.email == "person.name+contest@example.com"


@pytest.mark.parametrize(
    "email", ["person@example.com", "Person@Example.com", "PERSON@EXAMPLE.COM"]
)
def test_login_and_recovery_ignore_email_case(
    account, email, django_capture_on_commit_callbacks
):
    client = APIClient()
    response = client.post(
        reverse("login"), {"email": email, "password": "Original!73"}
    )
    assert response.status_code == 200
    assert Token.objects.get(key=response.data["token"]).user_id == account.pk

    with django_capture_on_commit_callbacks(execute=True):
        response = client.post(reverse("user-request-password-reset"), {"email": email})
    assert response.status_code == 200
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == [account.email]


@pytest.mark.parametrize("active", [False, True], ids=["activation", "password-reset"])
def test_email_links_survive_address_normalization(account, active):
    account.email = "Person@Example.com"
    account.is_active = active
    account.save(update_fields=["email", "is_active"])
    token = (
        generate_reset_token(account) if active else generate_activation_token(account)
    )
    User.objects.filter(pk=account.pk).update(email="person@example.com")

    endpoint = "user-password-reset" if active else "user-activate-account"
    payload = {"token": token}
    if active:
        payload["new_password"] = "Replacement!73"
    response = APIClient().post(reverse(endpoint), payload)

    assert response.status_code == 200
    account.refresh_from_db()
    assert account.email == "person@example.com"
    assert account.is_active
    if active:
        assert account.check_password("Replacement!73")


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


def wait_until_blocked_by_this_connection(pid):
    """Wait until database backend ``pid`` waits for a lock this connection holds."""
    deadline = time.monotonic() + 10
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_backend_pid()")
        (own_pid,) = cursor.fetchone()
        while True:
            cursor.execute("SELECT pg_blocking_pids(%s)", [pid])
            if own_pid in cursor.fetchone()[0]:
                return
            if time.monotonic() > deadline:
                pytest.fail("The other connection never waited for this one.")
            time.sleep(0.01)


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

    with patch("drf_user.serializers.authenticate", authenticate_then_replace_password):
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


def registration(email, address):
    """Return a valid registration request for a new account."""
    return {
        "email": email,
        "password": "Original!73",
        "first_name": "New",
        "last_name": "Account",
        **address,
    }


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
