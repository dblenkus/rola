"""Filter the payment API endpoint."""

from django_filters import rest_framework as filters

from rola.payments.models import Payment


class PaymentFilter(filters.FilterSet):
    """Filter for Submission API endpoint."""

    class Meta:
        """Configure submission-set and payment-status lookups."""

        model = Payment
        fields = {
            "submission_set": ["exact", "in"],
            "paid": ["exact"],
        }
