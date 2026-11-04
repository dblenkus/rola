"""Load the host configuration from the deployment environment."""

import io
import logging
import os
import runpy
from unittest.mock import patch

import pytest
from django.test import Client

import rola.settings
from rola.environment import boolean

SES_ENVIRONMENT = {
    "ROLA_SECRET_KEY": "test-only-secret-key",
    "ROLA_USE_SES": "true",
    "ROLA_SES_ACCESS_KEY_ID": "test-access-key-id",
    "ROLA_SES_SECRET_ACCESS_KEY": "test-secret-access-key",
}


@pytest.fixture
def load_settings(monkeypatch):
    """Execute the host settings module with only the given variables set."""
    for name in [name for name in os.environ if name.startswith("ROLA_")]:
        monkeypatch.delenv(name)

    def load(variables):
        for name, value in variables.items():
            monkeypatch.setenv(name, value)
        return runpy.run_path(rola.settings.__file__)

    return load


def test_ses_requires_a_sender_address(load_settings):
    with pytest.raises(KeyError, match="ROLA_DEFAULT_FROM_EMAIL"):
        load_settings(SES_ENVIRONMENT)


def test_ses_sends_from_the_configured_sender_over_ssl(load_settings):
    loaded = load_settings(
        SES_ENVIRONMENT | {"ROLA_DEFAULT_FROM_EMAIL": "contest@example.org"}
    )
    assert loaded["DEFAULT_FROM_EMAIL"] == "contest@example.org"
    mailer = loaded["MAILERS"]["default"]
    assert mailer["BACKEND"] == "django.core.mail.backends.smtp.EmailBackend"
    assert mailer["OPTIONS"] == {
        "host": "email-smtp.eu-west-1.amazonaws.com",
        "port": 465,
        "username": "test-access-key-id",
        "password": "test-secret-access-key",
        "use_ssl": True,
        "timeout": 10,
    }


def test_settings_reject_an_empty_boolean(load_settings):
    with pytest.raises(ValueError, match="ROLA_DEBUG"):
        load_settings({"ROLA_SECRET_KEY": "test-only-secret-key", "ROLA_DEBUG": ""})


@pytest.mark.parametrize(
    ("value", "expected"),
    [("true", True), ("On", True), ("1", True), ("FALSE", False), ("0", False)],
)
def test_boolean_accepts_common_spellings(monkeypatch, value, expected):
    monkeypatch.setenv("ROLA_FLAG", value)
    assert boolean("ROLA_FLAG") is expected


def test_boolean_is_false_when_unset(monkeypatch):
    monkeypatch.delenv("ROLA_FLAG", raising=False)
    assert boolean("ROLA_FLAG") is False


@pytest.mark.parametrize("value", ["", " ", "enabled"])
def test_boolean_rejects_ambiguous_values(monkeypatch, value):
    monkeypatch.setenv("ROLA_FLAG", value)
    with pytest.raises(ValueError, match="ROLA_FLAG must be a boolean"):
        boolean("ROLA_FLAG")


@pytest.mark.django_db
def test_server_errors_are_logged_to_the_console():
    handlers = logging.getLogger("django.request").handlers
    (handler,) = [handler for handler in handlers if handler.name == "console"]
    console = io.StringIO()
    previous_stream = handler.setStream(console)
    try:
        with patch(
            "rolca.core.api.views.ContestViewSet.list",
            side_effect=RuntimeError("database unavailable"),
        ):
            response = Client(raise_request_exception=False).get("/api/v1/contest")
    finally:
        handler.setStream(previous_stream)
    assert response.status_code == 500
    assert "Internal Server Error: /api/v1/contest" in console.getvalue()
    assert "RuntimeError: database unavailable" in console.getvalue()


def test_static_and_media_urls_are_the_paths_nginx_serves(load_settings):
    loaded = load_settings(
        {
            "ROLA_SECRET_KEY": "test-only-secret-key",
            "ROLA_FRONTEND_URL": "https://photos.example.org",
            "ROLA_STATIC_URL": "https://static.example.org/",
            "ROLA_MEDIA_URL": "https://media.example.org/",
        }
    )
    assert loaded["STATIC_URL"] == "/static2/"
    assert loaded["MEDIA_URL"] == "/media/"
