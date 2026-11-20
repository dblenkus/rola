"""Filter the entries API endpoints."""

from django_filters import rest_framework as filters

from rola.common.filters import IdFilter


class SubmissionFilter(filters.FilterSet):
    """Filter the requester's submissions by contest."""

    contest = IdFilter(field_name="theme__contest")


class SubmissionSetFilter(filters.FilterSet):
    """Filter submission sets by contest."""

    contest = IdFilter()
