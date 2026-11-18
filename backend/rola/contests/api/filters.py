"""Filter the contest and institution endpoints."""

from django_filters import rest_framework as filters

from rola.contests.models import Institution, Theme

TEXT_LOOKUPS = [
    "exact",
    "iexact",
    "contains",
    "icontains",
    "startswith",
    "istartswith",
]


class InstitutionFilter(filters.FilterSet):
    """Filter for Institutuion API endpoint."""

    class Meta:
        """Configure supported institution lookups."""

        model = Institution
        fields = {
            "name": TEXT_LOOKUPS[:],
            "kind": ["exact"],
        }


class ContestFilter(filters.FilterSet):
    """Filter for Contest API endpoint."""

    def filter_is_active(self, queryset, name, value):
        """Return active contests."""
        return queryset.active() if value else queryset.inactive()

    def filter_submitted(self, queryset, name, value):
        """Return contests to which current user has submitted to."""
        if self.request.user.is_anonymous:
            return queryset.none() if value else queryset

        contests = Theme.objects.filter(submission__user=self.request.user).values(
            "contest"
        )
        if value:
            return queryset.filter(pk__in=contests)
        return queryset.exclude(pk__in=contests)

    is_active = filters.BooleanFilter(method="filter_is_active")
    submitted = filters.BooleanFilter(method="filter_submitted")
