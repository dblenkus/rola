"""List the payment API routes."""

from rola.payments.api.views import (
    PaymentViewSet,
)

routeList = ((r"payment", PaymentViewSet),)
