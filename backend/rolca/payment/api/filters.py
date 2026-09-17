""".. Ignore pydocstyle D400.

===================
Payment API filters
===================

"""

from django_filters import rest_framework as filters

from rolca.payment.models import Payment


class PaymentFilter(filters.FilterSet):
    """Filter for Submission API endpoint."""

    class Meta:
        """Configure submission-set and payment-status lookups."""

        model = Payment
        fields = {
            "submissionset": ["exact", "in"],
            "paid": ["exact"],
        }
