"""Permissions classes."""
from rest_framework import permissions


class IsTargetUser(permissions.BasePermission):
    """Permission class for user endpoint."""

    def has_object_permission(self, request, view, obj):
        """"""
        return obj == request.user


class IsSuperUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        """"""
        return request.user.is_superuser
