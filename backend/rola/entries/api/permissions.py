""".. Ignore pydocstyle D400.

=======================
Entries API permissions
=======================

.. autoclass:: rola.entries.api.permissions.IsSubmissionOwnerOrReadOnly
    :members:

"""

from rest_framework import exceptions, permissions


def require_open_contest(contest):
    """Answer 403 unless the contest accepts entries.

    :raises PermissionDenied: If the contest does not accept entries now.
    """
    if not contest.accepts_entries():
        raise exceptions.PermissionDenied("This contest is not accepting entries.")


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
