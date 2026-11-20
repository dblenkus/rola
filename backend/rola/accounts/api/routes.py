"""Register the accounts API endpoints on the API router."""

from rest_framework.routers import BaseRouter

from rola.accounts.api.views import (
    ActivationViewSet,
    PasswordResetRequestViewSet,
    PasswordResetViewSet,
    TokenViewSet,
    UserViewSet,
)


def register(router: BaseRouter) -> None:
    """Register the login, logout, registration, activation and password reset endpoints."""
    router.register("tokens", TokenViewSet, basename="token")
    router.register("users", UserViewSet, basename="user")
    router.register("activations", ActivationViewSet, basename="activation")
    router.register(
        "password-reset-requests",
        PasswordResetRequestViewSet,
        basename="password-reset-request",
    )
    router.register("password-resets", PasswordResetViewSet, basename="password-reset")
