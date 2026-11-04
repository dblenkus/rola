"""Application configuration."""

from django.apps import AppConfig


class RolcaCoreConfig(AppConfig):
    """Application configuration."""

    default_auto_field = "django.db.models.AutoField"

    name = "rolca.core"
    verbose_name = "Rolca core"
