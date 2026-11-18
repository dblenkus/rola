""".. Ignore pydocstyle D400."""

from rest_framework import viewsets

from rola.common.permissions import IsSuperUser
from rola.payments.api.filters import PaymentFilter
from rola.payments.api.serializers import PaymentSerializer
from rola.payments.models import Payment


class PaymentViewSet(viewsets.ModelViewSet):
    """API viewset for Payment objects."""

    queryset = Payment.objects.order_by("pk")
    serializer_class = PaymentSerializer
    permission_classes = (IsSuperUser,)
    filterset_class = PaymentFilter
