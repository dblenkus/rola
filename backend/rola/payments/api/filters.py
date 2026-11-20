"""Filter the payment API endpoint."""

from django_filters import rest_framework as filters

from rola.common.filters import IdInFilter


class PaymentFilter(filters.FilterSet):
    """Filter payments by their submission sets."""

    submission_set__in = IdInFilter(field_name="submission_set", lookup_expr="in")
