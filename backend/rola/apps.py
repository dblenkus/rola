"""Application configuration of the Rola host."""

from django.contrib.admin.apps import AdminConfig


class RolaAdminConfig(AdminConfig):
    """Install the rate-limited admin site as ``django.contrib.admin.site``."""

    default_site = "rola.admin.RolaAdminSite"
