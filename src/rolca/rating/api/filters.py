""".. Ignore pydocstyle D400.

==================
Rating API filters
==================

"""

from django_filters import rest_framework as filters

from rolca.rating.models import Rating


class RatingFilter(filters.FilterSet):
    """Filter for Submission API endpoint."""

    theme = filters.CharFilter(field_name="submission__theme")

    class Meta:
        """Filter ratings by submission."""

        model = Rating
        fields = {
            "submission": ["exact"],
        }
