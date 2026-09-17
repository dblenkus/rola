""".. Ignore pydocstyle D400.

==============
Core API views
==============

"""

from django.utils import timezone
from django_filters import rest_framework as filters

from rolca.core.models import Institution, Submission, SubmissionSet

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


class SubmissionFilter(filters.FilterSet):
    """Filter for Submission API endpoint."""

    contest = filters.CharFilter(field_name="theme__contest")

    class Meta:
        """Configure submission filters."""

        model = Submission
        fields = ["theme"]


class SubmissionSetFilter(filters.FilterSet):
    """Filter for SubmissionSet API endpoint."""

    class Meta:
        """Filter submission sets by contest."""

        model = SubmissionSet
        fields = ["contest"]


class ContestFilter(filters.FilterSet):
    """Filter for Contest API endpoint."""

    def filter_is_active(self, queryset, name, value):
        """Return active contests."""
        now = timezone.now()
        filters = {"start_date__lte": now, "end_date__gte": now}
        return queryset.filter(**filters) if value else queryset.exclude(**filters)

    def filter_submitted(self, queryset, name, value):
        """Return contests to which current user has submitted to."""
        if self.request.user.is_anonymous:
            return queryset.none() if value else queryset

        filters = {"themes__submission__user": self.request.user}
        return queryset.filter(**filters) if value else queryset.exclude(**filters)

    is_active = filters.BooleanFilter(method="filter_is_active")
    submitted = filters.BooleanFilter(method="filter_submitted")
