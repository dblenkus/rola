""".. Ignore pydocstyle D400.

=============
Core API URLs
=============

``routeList`` pairs URL prefixes with the core API viewsets.
``rola.config.urls`` registers every pair, together with the payment and
rating lists, on the API router under ``/api/v1/``.

"""

from rola.contests.api.views import (
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
