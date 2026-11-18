"""Treat account email addresses as equal regardless of letter case."""

import pytest
from django.core import mail
from django.db import IntegrityError, transaction
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from rola.accounts.models import Location, Token, User
from rola.accounts.utils.signing import (
    generate_activation_token,
    generate_reset_token,
)
from tests.factories import first_link


@override_settings(ROLA_FRONTEND_URL="https://photos.example.com/")
@pytest.mark.parametrize("stored_email", ["person@example.com", "Person@Example.com"])
def test_registration_checks_uniqueness_against_stored_case(
    account, address, stored_email, django_capture_on_commit_callbacks
):
    User.objects.filter(pk=account.pk).update(email=stored_email)
    with django_capture_on_commit_callbacks(execute=True):
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
    assert response.status_code == 201
    assert response.content == b""
    assert User.objects.count() == 1
    assert not Location.objects.exists()
    (message,) = mail.outbox
    assert message.to == [stored_email]
    assert first_link(message).startswith("https://photos.example.com/password-reset?")


def test_database_rejects_addresses_that_differ_only_in_case(account):
    with (
        pytest.raises(IntegrityError, match="accounts_email_ci_unique"),
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
