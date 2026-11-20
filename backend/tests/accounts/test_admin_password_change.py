"""Revoke old credentials and limit guessing on the admin password change."""

import queue
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import connection, transaction
from django.test import Client, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from rola.accounts.forms import RolaAdminPasswordChangeForm
from rola.accounts.models import User
from rola.accounts.utils.signing import generate_reset_token
from tests.factories import (
    PASSWORD,
    create_user,
    logged_in_client,
    wait_until_blocked_by_this_connection,
)

pytestmark = pytest.mark.django_db

NEW_PASSWORD = "Replacement!73"

WRONG_PASSWORD = {"username": "organizer@example.org", "password": "wrong"}


@pytest.fixture
def organizer():
    """Create the staff account whose password the tests change."""
    return create_user("organizer", superuser=True)


@pytest.fixture
def browser(organizer):
    """Open the browser session that changes the organizer's password."""
    return signed_in(organizer)


def signed_in(user):
    """Open a browser session that is logged in as the given account."""
    browser = Client()
    browser.force_login(user)
    return browser


def change_password(browser, old_password=PASSWORD, **extra):
    """Post the admin password-change form, asking for ``NEW_PASSWORD``."""
    return browser.post(
        reverse("admin:password_change"),
        {
            "old_password": old_password,
            "new_password1": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        },
        **extra,
    )


def is_authenticated(client):
    """Tell whether the API accepts the client's login token."""
    status = client.get(reverse("submission-list")).status_code
    assert status in {200, 401}
    return status == 200


def redeem(reset_token):
    """Follow a password-reset link, asking for another password."""
    return APIClient().post(
        reverse("password-reset-list"),
        {"token": reset_token, "new_password": "Another!73"},
    )


def admin_login(**extra):
    """Post wrong credentials to the admin login from a fresh browser session."""
    return Client().post(reverse("admin:login"), WRONG_PASSWORD, **extra)


def api_login(**extra):
    """Post wrong API credentials."""
    credentials = {"email": "organizer@example.org", "password": "wrong"}
    return APIClient().post(reverse("token-list"), credentials, **extra)


def test_password_change_revokes_every_login_token_of_the_account(organizer, browser):
    phone, laptop = logged_in_client(organizer), logged_in_client(organizer)
    bystander = logged_in_client(create_user("entrant"))
    assert is_authenticated(phone)
    assert is_authenticated(laptop)

    response = change_password(browser)

    assert response.status_code == 302
    assert response.url == reverse("admin:password_change_done")
    assert not is_authenticated(phone)
    assert not is_authenticated(laptop)
    assert is_authenticated(bystander)


def test_password_change_invalidates_an_outstanding_reset_link(organizer, browser):
    reset_token = generate_reset_token(organizer)

    assert change_password(browser).status_code == 302
    response = redeem(reset_token)

    assert response.status_code == 400
    organizer.refresh_from_db()
    assert organizer.check_password(NEW_PASSWORD)


def test_password_change_keeps_the_session_that_made_it_logged_in(organizer, browser):
    assert change_password(browser).status_code == 302

    index = browser.get(reverse("admin:index"))

    assert index.status_code == 200
    assert index.wsgi_request.user == organizer


def test_password_change_logs_out_the_other_sessions_of_the_account(organizer, browser):
    elsewhere = signed_in(organizer)
    assert elsewhere.get(reverse("admin:index")).status_code == 200

    assert change_password(browser).status_code == 302

    index = elsewhere.get(reverse("admin:index"))
    assert index.status_code == 302
    assert index.url == f"{reverse('admin:login')}?next={reverse('admin:index')}"


def test_wrong_old_password_changes_and_revokes_nothing(organizer, browser):
    api = logged_in_client(organizer)
    reset_token = generate_reset_token(organizer)

    response = change_password(browser, old_password="wrong")

    assert response.status_code == 200
    organizer.refresh_from_db()
    assert organizer.check_password(PASSWORD)
    assert is_authenticated(api)
    assert redeem(reset_token).status_code == 204


def test_password_change_attempts_beyond_the_budget_are_refused(
    budget, organizer, browser
):
    assert change_password(browser, old_password="wrong").status_code == 200
    assert change_password(browser, old_password="wrong").status_code == 200
    response = change_password(browser)

    assert response.status_code == 429
    assert 0 < int(response.headers["Retry-After"]) <= 3600
    organizer.refresh_from_db()
    assert organizer.check_password(PASSWORD)


@pytest.mark.parametrize(
    ("login", "failed_login"), [(admin_login, 200), (api_login, 400)]
)
def test_login_attempts_use_up_the_password_change_budget(
    budget, organizer, browser, login, failed_login
):
    assert login().status_code == failed_login
    assert login().status_code == failed_login
    response = change_password(browser)

    assert response.status_code == 429
    organizer.refresh_from_db()
    assert organizer.check_password(PASSWORD)


@pytest.mark.parametrize("login", [admin_login, api_login])
def test_password_change_attempts_use_up_the_login_budget(budget, browser, login):
    assert change_password(browser, old_password="wrong").status_code == 200
    assert change_password(browser, old_password="wrong").status_code == 200

    assert login().status_code == 429


@pytest.mark.parametrize(
    ("num_proxies", "statuses"),
    [(0, [200, 200, 429, 429]), (1, [200, 200, 200, 429])],
)
def test_password_change_counts_forwarded_clients_only_behind_trusted_proxies(
    budget, browser, num_proxies, statuses
):
    addresses = ["198.51.100.1", "198.51.100.1", "198.51.100.2", "198.51.100.1"]
    with override_settings(
        REST_FRAMEWORK={**settings.REST_FRAMEWORK, "NUM_PROXIES": num_proxies}
    ):
        attempts = [
            change_password(
                browser, old_password="wrong", HTTP_X_FORWARDED_FOR=address
            ).status_code
            for address in addresses
        ]
    assert attempts == statuses


def test_password_change_page_is_never_throttled(budget, browser):
    url = reverse("admin:password_change")

    pages = [browser.get(url).status_code for _ in range(3)]
    attempts = [
        change_password(browser, old_password="wrong").status_code for _ in range(3)
    ]
    response = browser.get(url)

    assert pages == [200, 200, 200]
    assert attempts == [200, 200, 429]
    assert response.status_code == 200
    assert 'name="old_password"' in response.text


def test_password_change_form_refuses_to_leave_the_change_unsaved(organizer):
    form = RolaAdminPasswordChangeForm(
        organizer,
        {
            "old_password": PASSWORD,
            "new_password1": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        },
    )
    assert form.is_valid()

    with pytest.raises(ValueError, match="cannot be left unsaved"):
        form.save(commit=False)

    organizer.refresh_from_db()
    assert organizer.check_password(PASSWORD)


def test_password_change_form_refuses_a_password_replaced_since_validation(organizer):
    form = RolaAdminPasswordChangeForm(
        organizer,
        {
            "old_password": PASSWORD,
            "new_password1": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        },
    )
    assert form.is_valid()
    elsewhere = User.objects.get(pk=organizer.pk)
    elsewhere.set_password("Elsewhere!73")
    elsewhere.save()

    with pytest.raises(PermissionDenied):
        form.save()

    organizer.refresh_from_db()
    assert organizer.check_password("Elsewhere!73")


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_password_change_form_waits_for_a_change_that_holds_the_row():
    organizer = create_user("organizer", superuser=True)
    form = RolaAdminPasswordChangeForm(
        organizer,
        {
            "old_password": PASSWORD,
            "new_password1": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        },
    )
    assert form.is_valid()
    backend_pids = queue.SimpleQueue()

    def save_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return form.save()
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            elsewhere = User.objects.select_for_update().get(pk=organizer.pk)
            elsewhere.set_password("Elsewhere!73")
            elsewhere.save()
            save = executor.submit(save_on_another_connection)
            # Without the lock the form would read the old password here
            # and overwrite the new one once this transaction commits.
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        with pytest.raises(PermissionDenied):
            save.result(timeout=10)

    organizer.refresh_from_db()
    assert organizer.check_password("Elsewhere!73")
