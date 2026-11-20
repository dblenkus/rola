"""Filter the payment API endpoint."""

from django_filters import rest_framework as filters

from rola.common.filters import IdFilter, IdInFilter
from rola.payments.models import Payment


class PaymentFilter(filters.FilterSet):
    """Filter payments by submission set and payment status."""

    submission_set = IdFilter()
    submission_set__in = IdInFilter(field_name="submission_set", lookup_expr="in")

    class Meta:
        """Configure the payment-status lookup."""

        model = Payment
        fields = {
            "paid": ["exact"],
        }
