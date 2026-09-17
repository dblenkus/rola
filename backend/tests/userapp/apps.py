"""Configuration for the test host's authentication models."""

from django.apps import AppConfig


class UserAppConfig(AppConfig):
    """Provide the historical app label required by Rolca's migrations."""

    name = 'tests.userapp'
    label = 'drf_user'
    default_auto_field = 'django.db.models.AutoField'
