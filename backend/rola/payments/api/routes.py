"""Register the payment API endpoint on the API router."""

from rest_framework.routers import BaseRouter

from rola.payments.api.views import PaymentViewSet


def register(router: BaseRouter) -> None:
    """Register the payment endpoint, whose items are named by submission set."""
    router.register("payments", PaymentViewSet, basename="payment")
