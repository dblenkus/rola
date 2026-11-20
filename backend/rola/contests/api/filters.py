"""Filter the contest list."""

from django_filters import rest_framework as filters


class ContestFilter(filters.FilterSet):
    """Filter contests by whether they take entries now."""

    def filter_is_active(self, queryset, name, value):
        """Return active contests, or the others when ``value`` is false."""
        return queryset.active() if value else queryset.inactive()

    is_active = filters.BooleanFilter(method="filter_is_active")
