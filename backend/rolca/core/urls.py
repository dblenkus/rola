""".. Ignore pydocstyle D400.

=========
Core URLs
=========

"""

from django.urls import path

from . import views

app_name = "rolca-core-api"
urlpatterns = [
    path(
        "contest/<int:contest_id>/download",
        views.download_contest,
        name="download-contest",
    )
]
