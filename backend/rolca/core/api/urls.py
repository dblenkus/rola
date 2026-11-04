""".. Ignore pydocstyle D400.

=============
Core API URLs
=============

``routeList`` pairs URL prefixes with the core API viewsets.
``rolca.urls.route_lists`` collects it together with the payment and
rating lists, and ``rola.urls`` registers every pair on the host's API
router under ``/api/v1/``.

"""

from rolca.core.api.views import (
    AuthorViewSet,
    ContestViewSet,
    FileViewSet,
    InstitutionViewSet,
    SubmissionSetViewSet,
    SubmissionViewSet,
)

routeList = (
    (r"author", AuthorViewSet),
    (r"file", FileViewSet),
    (r"submission", SubmissionViewSet),
    (r"submissionset", SubmissionSetViewSet),
    (r"contest", ContestViewSet),
    (r"institution", InstitutionViewSet),
)
