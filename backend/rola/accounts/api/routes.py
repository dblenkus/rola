"""Register the accounts API endpoints on the API router."""

from django.urls import path
from rest_framework.routers import BaseRouter

from rola.accounts.api.views import LoginView, LogoutView, UserViewSet

# Plain views outside the router, which the project includes before the
# router's paths. The router's ``user/<id>`` detail route takes only a UUID,
# so it matches neither.
urlpatterns = [
    path("user/login", LoginView.as_view(), name="login"),
    path("user/logout", LogoutView.as_view(), name="logout"),
]


def register(router: BaseRouter, user_viewset: type[UserViewSet]) -> None:
    """Register the account endpoints.

    :param router: The API router.
    :param user_viewset: ``UserViewSet`` or the subclass that adds the
        project's rules, such as ``rola.entries.api.accounts.UserViewSet``.
    """
    router.register("user", user_viewset, basename="user")
