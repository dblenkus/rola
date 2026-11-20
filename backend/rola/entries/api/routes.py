"""Register the entries API endpoints on the API router."""

from rest_framework.routers import BaseRouter

from rola.entries.api.views import (
    AuthorViewSet,
    FileViewSet,
    SubmissionSetViewSet,
    SubmissionViewSet,
)


def register(router: BaseRouter) -> None:
    """Register the author, file, submission and submission set endpoints."""
    router.register("authors", AuthorViewSet, basename="author")
    router.register("files", FileViewSet, basename="file")
    router.register("submissions", SubmissionViewSet, basename="submission")
    router.register("submission-sets", SubmissionSetViewSet, basename="submission-set")
