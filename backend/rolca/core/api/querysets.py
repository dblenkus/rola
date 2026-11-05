"""Prepare related data shared by submission read endpoints."""

from django.db.models import QuerySet

from rolca.core.models import Submission


def with_submission_details(queryset: QuerySet[Submission]) -> QuerySet[Submission]:
    """Load the author account and uploaded files that submission responses read.

    :param queryset: Submissions with the caller's visibility filters and ordering.
    :return: The queryset with these related objects prepared for serialization.
    """
    return queryset.select_related("author__user").prefetch_related("files")
