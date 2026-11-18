""".. Ignore pydocstyle D400.

=================
Contests API URLs
=================

``routeList`` pairs URL prefixes with the contests API viewsets.
``rola.config.urls`` registers every pair, together with the entries,
payment and rating lists, on the API router under ``/api/v1/``.

"""

from rola.contests.api.views import ContestViewSet, InstitutionViewSet

routeList = (
    (r"contest", ContestViewSet),
    (r"institution", InstitutionViewSet),
)
