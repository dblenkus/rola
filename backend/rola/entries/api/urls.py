"""List the entries API routes, which rola.config.urls registers."""

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
