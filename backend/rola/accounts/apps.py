"""Application configurations of the accounts app and the admin site."""

from django.apps import AppConfig
from django.contrib.admin import apps as admin_apps


class AccountsConfig(AppConfig):
    """Users, tokens and account emails."""

    # Django picks the default AppConfig of a module that defines several.
    default = True
    name = "rola.accounts"


class RolaAdminConfig(admin_apps.AdminConfig):
    """Install the rate-limited admin site as ``django.contrib.admin.site``."""

    default = False
    default_site = "rola.accounts.sites.RolaAdminSite"
