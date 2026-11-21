"""Filter API lists by integer ids in the databases' 64-bit range."""

from typing import Any

from django import forms
from django_filters import rest_framework as django_filters

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
