""".. Ignore pydocstyle D400.

====================
Core API permissions
====================

.. autoclass:: rolca.core.api.permissions.AdminOrReadOnly
    :members:

"""

from django.utils import timezone
from rest_framework import permissions


class IsSubmissionOwnerOrReadOnly(permissions.BasePermission):
    """Allow writes only by the owner before publication."""

    def has_object_permission(self, request, view, obj):
        """Separate visibility of published submissions from write access."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return (
            obj.user_id == request.user.pk
            and obj.theme.contest.publish_date > timezone.now()
        )


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
