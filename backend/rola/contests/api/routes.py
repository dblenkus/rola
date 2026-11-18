"""Register the contests API endpoints on the API router."""

from rest_framework.routers import BaseRouter

from rola.contests.api.views import ContestViewSet, InstitutionViewSet


def register(router: BaseRouter) -> None:
    """Register the contest and institution endpoints."""
    router.register("contest", ContestViewSet, basename="contest")
    router.register("institution", InstitutionViewSet, basename="institution")
