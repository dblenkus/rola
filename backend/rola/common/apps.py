"""Application configuration of the common app."""

from django.apps import AppConfig


class CommonConfig(AppConfig):
    """Shared base classes and the readinesscheck command."""

    name = "rola.common"
