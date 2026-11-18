""".. Ignore pydocstyle D400.

===================
Entries API filters
===================

"""

from django_filters import rest_framework as filters

from rola.entries.models import Submission, SubmissionSet


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
