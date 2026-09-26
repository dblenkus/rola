"""Application configuration."""

from django.apps import AppConfig


class RolcaPaymentConfig(AppConfig):
    """Application configuration."""

    default_auto_field = "django.db.models.AutoField"

    name = "rolca.payment"
    verbose_name = "Rolca payment"
