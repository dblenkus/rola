""".. Ignore pydocstyle D400.

============
Entries URLs
============

"""

from django.urls import path

from . import views

app_name = "entries"
urlpatterns = [
    path(
        "contest/<int:contest_id>/download",
        views.download_contest,
        name="download-contest",
    )
]
