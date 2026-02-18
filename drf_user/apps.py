"""User configuration."""

from django.apps import AppConfig


class UserConfig(AppConfig):
    """User AppConfig."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'drf_user'
