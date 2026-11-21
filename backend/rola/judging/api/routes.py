"""Register the judging and results API endpoints on the API router."""

from rest_framework.routers import BaseRouter

from rola.judging.api.views import (
    JudgingContestViewSet,
    JudgingSubmissionViewSet,
    RatingViewSet,
    SubmissionResultsViewSet,
)


def register(router: BaseRouter) -> None:
    """Register the judging, rating and results endpoints."""
    router.register(
        "judging/contests", JudgingContestViewSet, basename="judging-contest"
    )
    router.register(
        "judging/submissions", JudgingSubmissionViewSet, basename="judging-submission"
    )
    router.register("judging/ratings", RatingViewSet, basename="judging-rating")
    router.register(
        "results/submissions", SubmissionResultsViewSet, basename="results-submission"
    )
