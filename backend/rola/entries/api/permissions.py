"""Check who may change entries and when."""

from rest_framework import permissions

from rola.entries.services import require_open_contest


class IsSubmissionOwnerOrReadOnly(permissions.BasePermission):
    """Allow writes only by the owner while the contest accepts entries."""

    def has_object_permission(self, request, view, obj):
        """Allow reads, and writes by the owner while the contest accepts entries.

        Deletes check the contest in the view.
        """
        if request.method in permissions.SAFE_METHODS:
            return True
        if obj.user_id != request.user.pk:
            return False
        if request.method != "DELETE":
            require_open_contest(obj.theme.contest)
        return True
