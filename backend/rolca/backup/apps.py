"""Application configuration."""

from django.apps import AppConfig


class RolcaBackupConfig(AppConfig):
    """Application configuration."""

    default_auto_field = 'django.db.models.AutoField'

    name = 'rolca.backup'
    verbose_name = "Rolca Backup"

    def ready(self):
        """Application initialization."""
        # Register signals handlers
        from . import signals  # noqa: F401
