"""Share cached state between server processes and keep sessions in the database."""

import pytest
from django.core.cache import caches
from django.db import connection
from django.test import Client
from django.urls import reverse

from drf_user.models import User

pytestmark = pytest.mark.django_db


def test_cached_values_are_stored_in_the_shared_database_table():
    caches["default"].set("login-attempts", [1, 2], 60)

    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM rola_cache")
        assert cursor.fetchone() == (1,)
    other_process_cache = caches.create_connection("default")
    assert other_process_cache is not caches["default"]
    assert other_process_cache.get("login-attempts") == [1, 2]


def test_admin_session_survives_clearing_the_cache():
    user = User.objects.create_superuser(
        "organizer@example.org", "test-only-A9!pass", first_name="Organizer"
    )
    browser = Client()
    browser.force_login(user)
    assert browser.get(reverse("admin:index")).status_code == 200

    caches["default"].clear()

    response = browser.get(reverse("admin:index"))
    assert response.status_code == 200
    assert response.wsgi_request.user == user
