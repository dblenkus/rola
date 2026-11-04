"""Register host-managed email templates."""

from django.contrib import admin

from drf_user.models import Email

admin.site.register(Email)
