""".. Ignore pydocstyle D400.

========================
Contests API permissions
========================

.. autoclass:: rola.contests.api.permissions.AdminOrReadOnly
    :members:

"""

from rest_framework import permissions


class IsSuperUser(permissions.BasePermission):
    """Allows access only to super-users."""

    def has_permission(self, request, view):
        """Return `True` if user in the request is super-user."""
        return request.user and request.user.is_superuser


class AdminOrReadOnly(permissions.BasePermission):
    """Permission class for DRF."""

    def has_permission(self, request, view):
        """Return `True` if method is safe or user is superuser."""
        return (
            request.method in permissions.SAFE_METHODS
            or request.user
            and request.user.is_superuser
        )
