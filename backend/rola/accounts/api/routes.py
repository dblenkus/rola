"""Register the accounts API endpoints on the API router."""

from django.urls import path
from rest_framework.routers import BaseRouter

from rola.accounts.api.views import LoginView, UserViewSet

# The router's ``user/<pk>`` detail route would also match this path, so the
# project includes these patterns before the router's.
urlpatterns = [
    path("user/login", LoginView.as_view(), name="login"),
]


def register(router: BaseRouter, user_viewset: type[UserViewSet]) -> None:
    """Register the account endpoints.

    :param router: The API router.
    :param user_viewset: ``UserViewSet`` or the subclass that adds the
        project's rules, such as ``rola.entries.api.accounts.UserViewSet``.
    """
    router.register("user", user_viewset, basename="user")
