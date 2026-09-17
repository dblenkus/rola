""".. Ignore pydocstyle D400.

=======================
Payment API serializers
=======================

.. autoclass:: rolca.payment.api.serializers.PaymentSerializer
    :members:

"""

from rolca.core.api.serializers import BaseSerializer
from rolca.payment.models import Payment


class PaymentSerializer(BaseSerializer):
    """Serializer for Payment objects."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Payment
        fields = BaseSerializer.Meta.fields + ['submissionset', 'paid']
        extra_kwargs = {'submissionset': {'validators': []}}

    def create(self, validated_data):
        """Create or update payment status for one submission set."""
        submissionset = validated_data.pop('submissionset')
        payment, _ = Payment.objects.update_or_create(
            submissionset=submissionset, defaults=validated_data
        )
        return payment
