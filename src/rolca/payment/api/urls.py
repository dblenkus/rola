""".. Ignore pydocstyle D400."""

from rolca.payment.api.views import (
    PaymentViewSet,
)

routeList = ((r'payment', PaymentViewSet),)
