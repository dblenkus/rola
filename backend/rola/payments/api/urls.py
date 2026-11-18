""".. Ignore pydocstyle D400."""

from rola.payments.api.views import (
    PaymentViewSet,
)

routeList = ((r"payment", PaymentViewSet),)
