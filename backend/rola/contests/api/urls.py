"""List the contests API routes, which rola.config.urls registers."""

from rola.contests.api.views import ContestViewSet, InstitutionViewSet

routeList = (
    (r"contest", ContestViewSet),
    (r"institution", InstitutionViewSet),
)
