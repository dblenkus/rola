"""Filter the rating API endpoint."""

from django_filters import rest_framework as filters

from rola.judging.models import Rating


class RatingFilter(filters.FilterSet):
    """Filter for Submission API endpoint."""

    theme = filters.CharFilter(field_name="submission__theme")

    class Meta:
        """Filter ratings by submission."""

        model = Rating
        fields = {
            "submission": ["exact"],
        }
