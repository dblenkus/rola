"""Filter backends for the API."""

from collections.abc import Sequence
from typing import Any

from django.db.models import QuerySet
from rest_framework import filters
from rest_framework.request import Request
from rest_framework.views import APIView


class OrderingFilter(filters.OrderingFilter):
    """Order by the requested fields with the primary key as the last key.

    Requested fields are seldom unique, and the database may return tied rows
    in a different order for each page unless a unique key comes last.
    """

    def get_ordering(
        self, request: Request, queryset: QuerySet[Any], view: APIView
    ) -> Sequence[str] | None:
        """Return the requested or view ordering followed by ``pk``."""
        ordering = super().get_ordering(request, queryset, view)
        return [*ordering, "pk"] if ordering else ordering
