"""User configuration."""
from django.apps import AppConfig


class UserConfig(AppConfig):
    """User AppConfig."""

    name = 'rola.user'

    def ready(self):
        """Application initialization."""
        # Register signals handlers
        from . import signals
