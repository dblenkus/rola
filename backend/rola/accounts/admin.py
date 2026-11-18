"""Register host-managed email templates."""

from django.contrib import admin

from rola.accounts.models import Email

admin.site.register(Email)
