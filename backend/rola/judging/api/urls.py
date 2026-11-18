""".. Ignore pydocstyle D400."""

from rola.judging.api.views import (
    ContestViewSet,
    RatingViewSet,
    SubmissionResultsViewSet,
    SubmissionViewSet,
    ThemeResultsViewSet,
)

routeList = (
    (r"rating", RatingViewSet),
    (r"judge/contest", ContestViewSet),
    (r"judge/submission", SubmissionViewSet),
    (r"results/theme", ThemeResultsViewSet),
    (r"results/submission", SubmissionResultsViewSet),
)
