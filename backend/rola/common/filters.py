"""Filter backends and filters shared by the API endpoints."""

from collections.abc import Sequence
from typing import Any

from django import forms
from django.db.models import QuerySet
from django_filters import rest_framework as django_filters
from rest_framework import filters
from rest_framework.request import Request
from rest_framework.views import APIView

from rola.common.ids import ID_RANGE


class IdField(forms.IntegerField):
    """Accept an integer id in the database's 64-bit range."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Bound the field to the range the databases store."""
        super().__init__(*args, **{**ID_RANGE, **kwargs})


# django-filter ships no type information, so its classes are Any to mypy.
class IdFilter(django_filters.NumberFilter):  # type: ignore[misc]
    """Filter by an integer id, answering 400 for any other value.

    ``NumberFilter`` alone takes decimals, so ``1.5`` would match the id 1,
    and an id too large for the database would fail with 500. An id that
    matches nothing selects no rows.
    """

    field_class = IdField


class IdInFilter(django_filters.BaseInFilter, IdFilter):  # type: ignore[misc]
    """Filter by a comma-separated list of integer ids."""


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
