"""Limit password guessing through the Django admin login."""

from unittest.mock import patch

import pytest
from django.conf import settings
from django.test import Client, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from drf_user.throttling import LoginThrottle
from tests.factories import PASSWORD, create_user

pytestmark = pytest.mark.django_db

WRONG_PASSWORD = {"username": "organizer@example.org", "password": "wrong"}


@pytest.fixture
def budget():
    """Allow two login attempts per client address."""
    with patch.object(LoginThrottle, "rate", "2/hour", create=True):
        yield


def admin_login(credentials, **extra):
    """Post the admin login form from a fresh browser session."""
    return Client().post(reverse("admin:login"), credentials, **extra)


def api_login(**extra):
    """Post wrong API credentials."""
    credentials = {"email": "organizer@example.org", "password": "wrong"}
    return APIClient().post(reverse("login"), credentials, **extra)


def test_admin_login_attempts_beyond_the_budget_are_refused(budget):
    create_user("organizer", superuser=True)
    correct = {"username": "organizer@example.org", "password": PASSWORD}

    assert admin_login(WRONG_PASSWORD).status_code == 200
    assert admin_login(WRONG_PASSWORD).status_code == 200
    response = admin_login(correct)

    assert response.status_code == 429
    assert 0 < int(response.headers["Retry-After"]) <= 3600
    assert "_auth_user_id" not in response.wsgi_request.session


def test_admin_login_inside_the_budget_logs_in(budget):
    organizer = create_user("organizer", superuser=True)
    browser = Client()
    url = reverse("admin:login")

    assert browser.post(url, WRONG_PASSWORD).status_code == 200
    response = browser.post(
        url, {"username": "organizer@example.org", "password": PASSWORD}
    )

    assert response.status_code == 302
    index = browser.get(reverse("admin:index"))
    assert index.status_code == 200
    assert index.wsgi_request.user == organizer


@pytest.mark.parametrize("first", ["admin", "api"])
def test_admin_and_api_logins_share_one_budget(budget, first):
    if first == "admin":
        assert admin_login(WRONG_PASSWORD).status_code == 200
        assert api_login().status_code == 400
        assert api_login().status_code == 429
    else:
        assert api_login().status_code == 400
        assert admin_login(WRONG_PASSWORD).status_code == 200
        assert admin_login(WRONG_PASSWORD).status_code == 429


@pytest.mark.parametrize(("num_proxies", "third_status"), [(0, 429), (1, 200)])
def test_admin_login_counts_forwarded_clients_only_behind_trusted_proxies(
    budget, num_proxies, third_status
):
    with override_settings(
        REST_FRAMEWORK={**settings.REST_FRAMEWORK, "NUM_PROXIES": num_proxies}
    ):
        statuses = [
            admin_login(WRONG_PASSWORD, HTTP_X_FORWARDED_FOR=address).status_code
            for address in ["198.51.100.1", "198.51.100.1", "198.51.100.2"]
        ]
    assert statuses == [200, 200, third_status]


def test_admin_login_page_is_never_throttled(budget):
    browser = Client()
    url = reverse("admin:login")

    pages = [browser.get(url).status_code for _ in range(3)]
    attempts = [admin_login(WRONG_PASSWORD).status_code for _ in range(3)]
    response = browser.get(url)

    assert pages == [200, 200, 200]
    assert attempts == [200, 200, 429]
    assert response.status_code == 200
    assert 'name="password"' in response.text
