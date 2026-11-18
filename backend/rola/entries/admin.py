"""Register the submitted entries in the Django admin."""

from django.contrib import admin

from rola.entries.models import File, Submission

admin.site.register(Submission)
admin.site.register(File)
