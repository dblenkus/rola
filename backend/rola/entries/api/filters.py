"""Filter the entries API endpoints."""

from django_filters import rest_framework as filters

from rola.common.filters import IdFilter


class SubmissionFilter(filters.FilterSet):
    """Filter for Submission API endpoint."""

    contest = IdFilter(field_name="theme__contest")
    theme = IdFilter()


class SubmissionSetFilter(filters.FilterSet):
    """Filter for SubmissionSet API endpoint."""

    contest = IdFilter()
