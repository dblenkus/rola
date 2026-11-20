"""Filter the rating API endpoint."""

from django_filters import rest_framework as filters

from rola.common.filters import IdFilter


class RatingFilter(filters.FilterSet):
    """Filter ratings by the theme or submission they rate."""

    theme = IdFilter(field_name="submission__theme")
    submission = IdFilter()
