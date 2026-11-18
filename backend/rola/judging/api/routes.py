"""Register the judging and results API endpoints on the API router."""

from rest_framework.routers import BaseRouter

from rola.judging.api.views import (
    ContestViewSet,
    RatingViewSet,
    SubmissionResultsViewSet,
    SubmissionViewSet,
    ThemeResultsViewSet,
)


def register(router: BaseRouter) -> None:
    """Register the rating, judging and results endpoints."""
    router.register("rating", RatingViewSet, basename="rating")
    router.register("judge/contest", ContestViewSet, basename="judge-contest")
    router.register("judge/submission", SubmissionViewSet, basename="judge-submission")
    router.register("results/theme", ThemeResultsViewSet, basename="results-theme")
    router.register(
        "results/submission", SubmissionResultsViewSet, basename="results-submission"
    )
