"""API permissions shared by the apps."""

from rest_framework import permissions


class IsSuperUser(permissions.BasePermission):
    """Allow access only to superusers."""

    def has_permission(self, request, view):
        """Require an authenticated superuser."""
        return request.user.is_authenticated and request.user.is_superuser

    def has_object_permission(self, request, view, obj):
        """Require an authenticated superuser."""
        return request.user.is_authenticated and request.user.is_superuser


class AdminOrReadOnly(permissions.BasePermission):
    """Permission class for DRF."""

    def has_permission(self, request, view):
        """Return `True` if method is safe or user is superuser."""
        return (
            request.method in permissions.SAFE_METHODS
            or request.user
            and request.user.is_superuser
        )
