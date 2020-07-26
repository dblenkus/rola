""".. Ignore pydocstyle D400.

==============
DRF User Admin
==============

"""
from django.contrib import admin

from drf_user.models import Email


admin.site.register(Email)
