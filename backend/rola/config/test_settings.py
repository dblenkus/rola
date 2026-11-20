"""Run the host configuration against isolated test services."""

import os

os.environ.setdefault("ROLA_SECRET_KEY", "test-only-secret-key-never-use-in-production")
os.environ.setdefault("ROLA_FRONTEND_URL", "https://photos.example.org")

from rola.config.environment import boolean  # noqa: E402
from rola.config.settings import *  # noqa: E402,F403

SECURE_SSL_REDIRECT = False
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
# The API accepts only JSON bodies, and the test client otherwise sends forms.
REST_FRAMEWORK = {**REST_FRAMEWORK, "TEST_REQUEST_DEFAULT_FORMAT": "json"}  # noqa: F405
if not boolean("ROLA_TEST_POSTGRESQL"):
    DATABASES = {
        "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
    }
