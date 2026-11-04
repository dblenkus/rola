"""Run the host configuration against isolated test services."""

import os

os.environ.setdefault("ROLA_SECRET_KEY", "test-only-secret-key-never-use-in-production")

from rola.environment import boolean  # noqa: E402
from rola.settings import *  # noqa: E402,F403

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
if not boolean("ROLA_TEST_POSTGRESQL"):
    DATABASES = {
        "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
    }
