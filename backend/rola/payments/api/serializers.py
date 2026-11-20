"""Serialize payments for the API."""

from typing import Any

from rola.common.serializers import BaseSerializer
from rola.payments.models import Payment


class PaymentSerializer(BaseSerializer):
    """Serializer for Payment objects."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Payment
        fields = BaseSerializer.Meta.fields + ["submission_set", "paid"]
        extra_kwargs: dict[str, dict[str, Any]] = {"submission_set": {"validators": []}}

    def create(self, validated_data):
        """Create or update payment status for one submission set."""
        submission_set = validated_data.pop("submission_set")
        payment, _ = Payment.objects.update_or_create(
            submission_set=submission_set, defaults=validated_data
        )
        return payment
