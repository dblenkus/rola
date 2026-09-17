"""Exercise credential and account isolation boundaries."""

from urllib.parse import parse_qs, urlsplit

import pytest
from django.core import mail
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from drf_user.models import Location, Token, User


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


def test_profile_password_write_is_rejected(client, account):
    response = client.patch(
        reverse("user-detail", kwargs={"id": account.id}),
        {"password": "Replacement!73"},
    )
    assert response.status_code == 400
    account.refresh_from_db()
    assert account.check_password("Original!73")


def test_location_creation_and_partial_update_are_atomic(client, account):
    url = reverse("user-detail", kwargs={"id": account.id})
    response = client.patch(url, {"city": "Ljubljana"})
    assert response.status_code == 400
    assert Location.objects.count() == 0
    response = client.patch(
        url,
        {
            "address": "Street 1",
            "city": "Ljubljana",
            "postal_code": "1000",
            "country": "SI",
        },
    )
    assert response.status_code == 200
    assert response.data["city"] == "Ljubljana"
    response = client.patch(url, {"city": "Maribor", "first_name": "Changed"})
    assert response.status_code == 200
    assert response.data["city"] == "Maribor"
    account.refresh_from_db()
    assert account.location.city == "Maribor"
    assert account.first_name == "Changed"
    assert Location.objects.count() == 1


def test_registration_validation_does_not_leave_an_address(db):
    payload = {
        "email": "new@example.com",
        "password": "short",
        "first_name": "New",
        "last_name": "Account",
        "address": "Street 1",
        "city": "Ljubljana",
        "postal_code": "1000",
        "country": "SI",
    }
    response = APIClient().post(reverse("user-list"), payload)
    assert response.status_code == 400
    assert not Location.objects.exists()
    assert not User.objects.exists()


def test_recovery_email_uses_configured_frontend(
    account, django_capture_on_commit_callbacks
):
    with (
        override_settings(ROLA_FRONTEND_URL="https://photos.example.com"),
        django_capture_on_commit_callbacks(execute=True),
    ):
        response = APIClient().post(
            reverse("user-request-password-reset"), {"email": account.email}
        )
    assert response.status_code == 200
    link = next(
        line for line in mail.outbox[0].body.splitlines() if line.startswith("https://")
    )
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
