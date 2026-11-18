"""Load the host configuration from the deployment environment."""

import io
import logging
import os
import runpy
from unittest.mock import patch
from urllib.parse import urljoin, urlsplit

import pytest
from django.test import Client, override_settings
from django.utils.module_loading import import_string

import rola.config.settings
from rola.config.environment import boolean

REQUIRED_ENVIRONMENT = {
    "ROLA_SECRET_KEY": "test-only-secret-key",
    "ROLA_FRONTEND_URL": "https://photos.example.org",
}
SES_ENVIRONMENT = REQUIRED_ENVIRONMENT | {
    "ROLA_USE_SES": "true",
    "ROLA_SES_ACCESS_KEY_ID": "test-access-key-id",
    "ROLA_SES_SECRET_ACCESS_KEY": "test-secret-access-key",
}

S3_ENVIRONMENT = REQUIRED_ENVIRONMENT | {
    "ROLA_USE_S3": "true",
    "ROLA_AWS_ACCESS_KEY_ID": "test-access-key-id",
    "ROLA_AWS_SECRET_ACCESS_KEY": "test-secret-access-key",
    "ROLA_AWS_REGION_NAME": "eu-west-1",
    "ROLA_AWS_MEDIA_STORAGE_BUCKET_NAME": "rola-media",
    "ROLA_AWS_STATIC_STORAGE_BUCKET_NAME": "rola-static",
}


@pytest.fixture
def load_settings(monkeypatch):
    """Execute the host settings module with only the given variables set."""
    for name in [name for name in os.environ if name.startswith("ROLA_")]:
        monkeypatch.delenv(name)

    def load(variables):
        for name, value in variables.items():
            monkeypatch.setenv(name, value)
        return runpy.run_path(rola.config.settings.__file__)

    return load


def test_account_email_links_require_the_frontend_url(load_settings):
    with pytest.raises(KeyError, match="ROLA_FRONTEND_URL"):
        load_settings({"ROLA_SECRET_KEY": "test-only-secret-key"})


@pytest.mark.parametrize(
    "value",
    [
        "",
        "photos.example.org",
        "/password-reset",
        "https://",
        "ftp://example.org",
        "https://photos.example.org/?lang=sl",
        "https://photos.example.org#top",
        "https://user@photos.example.org",
        "https://photos.example.org ",
        " https://photos.example.org",
    ],
)
def test_account_email_links_require_an_absolute_frontend_url(load_settings, value):
    with pytest.raises(ValueError, match="ROLA_FRONTEND_URL"):
        load_settings(REQUIRED_ENVIRONMENT | {"ROLA_FRONTEND_URL": value})


def test_account_email_links_accept_a_plain_http_frontend(load_settings):
    loaded = load_settings(
        REQUIRED_ENVIRONMENT | {"ROLA_FRONTEND_URL": "http://localhost:8080"}
    )
    assert loaded["ROLA_FRONTEND_URL"] == "http://localhost:8080"


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


def test_s3_requires_a_signing_region(load_settings):
    environment = dict(S3_ENVIRONMENT)
    del environment["ROLA_AWS_REGION_NAME"]
    with pytest.raises(KeyError, match="ROLA_AWS_REGION_NAME"):
        load_settings(environment)


def test_s3_media_urls_are_signed_with_sigv4(load_settings, monkeypatch, tmp_path):
    # Keep local AWS configuration files from changing the signer.
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    storage = load_settings(S3_ENVIRONMENT)["STORAGES"]["default"]
    url = import_string(storage["BACKEND"])(**storage["OPTIONS"]).url("photo.jpg")
    assert "X-Amz-Algorithm=AWS4-HMAC-SHA256" in url
    assert "%2Feu-west-1%2Fs3%2Faws4_request" in url
    assert "X-Amz-Expires=3600" in url


def test_s3_static_urls_are_unsigned(load_settings, monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    options = load_settings(S3_ENVIRONMENT)["STORAGES"]["staticfiles"]
    storage = import_string(options["BACKEND"])(**options["OPTIONS"])
    stylesheet = storage.url("admin/css/widgets.css")
    assert urlsplit(stylesheet).netloc.startswith("rola-static.")
    # The admin's stylesheets load their icons by relative URLs, which carry
    # no query string, so a signed stylesheet URL leaves the icons unsigned.
    icon = urljoin(stylesheet, "../img/calendar-icons.svg")
    assert icon == storage.url("admin/img/calendar-icons.svg")


def test_production_requires_https_and_distrusts_proxy_headers(load_settings):
    loaded = load_settings(REQUIRED_ENVIRONMENT)
    assert loaded["SECURE_SSL_REDIRECT"] is True
    assert loaded["SESSION_COOKIE_SECURE"] is True
    assert loaded["CSRF_COOKIE_SECURE"] is True
    assert loaded["SECURE_HSTS_SECONDS"] == 31_536_000
    assert "SECURE_PROXY_SSL_HEADER" not in loaded
    assert loaded["USE_X_FORWARDED_HOST"] is False
    assert loaded["REST_FRAMEWORK"]["NUM_PROXIES"] == 0
    assert loaded["CSRF_TRUSTED_ORIGINS"] == []


def test_debug_serves_plain_http(load_settings):
    loaded = load_settings(REQUIRED_ENVIRONMENT | {"ROLA_DEBUG": "true"})
    assert loaded["SECURE_SSL_REDIRECT"] is False
    assert loaded["SESSION_COOKIE_SECURE"] is False
    assert loaded["CSRF_COOKIE_SECURE"] is False
    assert loaded["SECURE_HSTS_SECONDS"] == 0


def test_proxy_trust_is_configured_explicitly(load_settings):
    loaded = load_settings(
        REQUIRED_ENVIRONMENT
        | {
            "ROLA_TRUST_PROXY": "true",
            "ROLA_USE_X_FORWARDED_HOST": "true",
            "ROLA_NUM_PROXIES": "2",
            "ROLA_CSRF_TRUSTED_ORIGINS": "https://photos.example.org, "
            "https://admin.example.org",
        }
    )
    assert loaded["SECURE_PROXY_SSL_HEADER"] == ("HTTP_X_FORWARDED_PROTO", "https")
    assert loaded["USE_X_FORWARDED_HOST"] is True
    assert loaded["REST_FRAMEWORK"]["NUM_PROXIES"] == 2
    assert loaded["CSRF_TRUSTED_ORIGINS"] == [
        "https://photos.example.org",
        "https://admin.example.org",
    ]


def test_settings_reject_an_empty_proxy_count(load_settings):
    with pytest.raises(ValueError, match="invalid literal for int"):
        load_settings(REQUIRED_ENVIRONMENT | {"ROLA_NUM_PROXIES": ""})


@pytest.mark.django_db
@pytest.mark.parametrize("trust_proxy", [False, True])
def test_forwarded_https_counts_only_behind_a_trusted_proxy(load_settings, trust_proxy):
    loaded = load_settings(
        REQUIRED_ENVIRONMENT | {"ROLA_TRUST_PROXY": str(trust_proxy).lower()}
    )
    with override_settings(
        SECURE_SSL_REDIRECT=loaded["SECURE_SSL_REDIRECT"],
        SECURE_HSTS_SECONDS=loaded["SECURE_HSTS_SECONDS"],
        SECURE_PROXY_SSL_HEADER=loaded.get("SECURE_PROXY_SSL_HEADER"),
    ):
        response = Client().get("/api/v1/contest", HTTP_X_FORWARDED_PROTO="https")
    if trust_proxy:
        assert response.status_code == 200
        assert response["Strict-Transport-Security"] == "max-age=31536000"
    else:
        assert response.status_code == 301
        assert response["Location"] == "https://testserver/api/v1/contest"


def test_settings_reject_an_empty_boolean(load_settings):
    with pytest.raises(ValueError, match="ROLA_DEBUG"):
        load_settings(REQUIRED_ENVIRONMENT | {"ROLA_DEBUG": ""})


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
            "rola.contests.api.views.ContestViewSet.list",
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
