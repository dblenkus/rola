"""Django host configuration from the deployment environment."""

import os
from pathlib import Path

from rola.environment import absolute_url, boolean, comma_separated

BASE_DIR = Path(__file__).resolve().parent.parent
DEBUG = boolean("ROLA_DEBUG")
SECRET_KEY = os.environ["ROLA_SECRET_KEY"]
ALLOWED_HOSTS = comma_separated("ALLOWED_HOSTS")
AUTH_USER_MODEL = "drf_user.User"
LOGIN_URL = "admin:login"

INSTALLED_APPS = [
    "rola.apps.RolaAdminConfig",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "django_filters",
    "drf_spectacular",
    "rolca.core",
    "rolca.payment",
    "rolca.rating",
    "drf_user.apps.UserConfig",
    "storages",
    "utils",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "rola.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]
WSGI_APPLICATION = "rola.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("ROLA_POSTGRESQL_NAME", "rola"),
        "USER": os.environ.get("ROLA_POSTGRESQL_USER", "rola"),
        "PASSWORD": os.environ.get("ROLA_POSTGRESQL_PASSWORD", ""),
        "HOST": os.environ.get("ROLA_POSTGRESQL_HOST", "postgresql"),
        "PORT": os.environ.get("ROLA_POSTGRESQL_PORT", "5432"),
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {"connect_timeout": 3},
    }
}
if boolean("ROLA_POSTGRESQL_SSLMODE"):
    DATABASES["default"]["OPTIONS"]["sslmode"] = "require"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "rola_cache",
        # A full cache culls a third of its unexpired keys in name order, login
        # throttle histories first, which would reset their limits.
        "OPTIONS": {"MAX_ENTRIES": 100_000},
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
if boolean("ROLA_DISABLE_PASSWORD_VALIDATORS"):
    AUTH_PASSWORD_VALIDATORS = []

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["drf_user.authentication.TokenAuthentication"],
    # The browsable API's forms list related objects from unfiltered querysets,
    # which would show any account the titles of every submission.
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticatedOrReadOnly",
    ),
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.backends.DjangoFilterBackend",
        "rola.filters.OrderingFilter",
    ),
    "DEFAULT_PAGINATION_CLASS": "rola.pagination.PageNumberPagination",
    "PAGE_SIZE": 500,
    "NUM_PROXIES": int(os.environ.get("ROLA_NUM_PROXIES", "0")),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_RATES": {
        "login": "30/minute",
        "registration": "60/hour",
        "activation": "60/hour",
        "recovery": "30/hour",
    },
}
SPECTACULAR_SETTINGS = {
    "TITLE": "Rola API",
    "DESCRIPTION": "Accounts, photography contests, submissions, judging and payments.",
    "VERSION": "1.0.0",
    "COMPONENT_SPLIT_REQUEST": True,
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

MAILERS = {
    "default": {
        "BACKEND": "django.core.mail.backends.console.EmailBackend"
        if DEBUG
        else "django.core.mail.backends.dummy.EmailBackend"
    }
}
if boolean("ROLA_USE_SES"):
    DEFAULT_FROM_EMAIL = os.environ["ROLA_DEFAULT_FROM_EMAIL"]
    MAILERS = {
        "default": {
            "BACKEND": "django.core.mail.backends.smtp.EmailBackend",
            "OPTIONS": {
                "host": os.environ.get(
                    "ROLA_SMTP_HOST", "email-smtp.eu-west-1.amazonaws.com"
                ),
                "port": int(os.environ.get("ROLA_SMTP_PORT", "465")),
                "username": os.environ["ROLA_SES_ACCESS_KEY_ID"],
                "password": os.environ["ROLA_SES_SECRET_ACCESS_KEY"],
                "use_ssl": True,
                "timeout": 10,
            },
        }
    }

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        }
    },
}

USE_X_FORWARDED_HOST = boolean("ROLA_USE_X_FORWARDED_HOST")
if boolean("ROLA_TRUST_PROXY"):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_HSTS_SECONDS = 0 if DEBUG else 31_536_000
CSRF_TRUSTED_ORIGINS = comma_separated("ROLA_CSRF_TRUSTED_ORIGINS")

MEDIA_URL = "/media/"
MEDIA_ROOT = Path(os.environ.get("ROLA_MEDIA_ROOT", BASE_DIR / "media"))
STATIC_URL = "/static2/"
STATIC_ROOT = Path(os.environ.get("ROLA_STATIC_ROOT", BASE_DIR / "static"))
if boolean("ROLA_USE_S3"):
    s3_options = {
        "access_key": os.environ.get("ROLA_AWS_ACCESS_KEY_ID"),
        "secret_key": os.environ.get("ROLA_AWS_SECRET_ACCESS_KEY"),
        "endpoint_url": os.environ.get("ROLA_AWS_S3_ENDPOINT_URL"),
        "region_name": os.environ["ROLA_AWS_REGION_NAME"],
        "signature_version": "s3v4",
        "default_acl": None,
        "object_parameters": {"CacheControl": "max-age=86400"},
    }
    STORAGES = {
        "default": {
            "BACKEND": "storages.backends.s3.S3Storage",
            "OPTIONS": {
                **s3_options,
                "bucket_name": os.environ["ROLA_AWS_MEDIA_STORAGE_BUCKET_NAME"],
                "file_overwrite": False,
            },
        },
        "staticfiles": {
            "BACKEND": "storages.backends.s3.S3Storage",
            "OPTIONS": {
                **s3_options,
                "bucket_name": os.environ["ROLA_AWS_STATIC_STORAGE_BUCKET_NAME"],
            },
        },
    }

DATA_UPLOAD_MAX_MEMORY_SIZE = 10_485_760
ROLCA_MAX_UPLOAD_SIZE = 5_242_880
ROLCA_MAX_UPLOAD_RESOLUTION = 3500
DRF_USER_APP_NAME = os.environ.get("ROLA_APP_NAME", "Rola")
ROLA_FRONTEND_URL = absolute_url("ROLA_FRONTEND_URL")
