"""API permissions shared by the apps."""

from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.views import APIView


class IsSuperUser(permissions.BasePermission):
    """Allow access only to superusers."""

    def has_permission(self, request: Request, view: APIView) -> bool:
        """Require an authenticated superuser."""
        return request.user.is_authenticated and request.user.is_superuser

    def has_object_permission(
        self, request: Request, view: APIView, obj: object
    ) -> bool:
        """Require an authenticated superuser."""
        return request.user.is_authenticated and request.user.is_superuser
