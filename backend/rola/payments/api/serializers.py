"""Serialize payments for the API."""

from typing import Any

from rola.common.serializers import BaseSerializer
from rola.payments.models import Payment


class PaymentSerializer(BaseSerializer):
    """Serialize a payment, whose submission set the request path names."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Payment
        fields = BaseSerializer.Meta.fields + ["submission_set", "paid"]
        read_only_fields = BaseSerializer.Meta.read_only_fields + ["submission_set"]
        extra_kwargs: dict[str, dict[str, Any]] = {"paid": {"required": True}}
