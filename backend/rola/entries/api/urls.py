""".. Ignore pydocstyle D400.

================
Entries API URLs
================

``routeList`` pairs URL prefixes with the entries API viewsets.
``rola.config.urls`` registers every pair, together with the contests,
payment and rating lists, on the API router under ``/api/v1/``.

"""

from rola.entries.api.views import (
    AuthorViewSet,
    FileViewSet,
    SubmissionSetViewSet,
    SubmissionViewSet,
)

routeList = (
    (r"author", AuthorViewSet),
    (r"file", FileViewSet),
    (r"submission", SubmissionViewSet),
    (r"submissionset", SubmissionSetViewSet),
)
