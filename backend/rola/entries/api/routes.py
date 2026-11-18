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
    router.register("author", AuthorViewSet, basename="author")
    router.register("file", FileViewSet, basename="file")
    router.register("submission", SubmissionViewSet, basename="submission")
    router.register("submissionset", SubmissionSetViewSet, basename="submissionset")
