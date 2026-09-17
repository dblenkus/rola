""".. Ignore pydocstyle D400.

======================
Rating API permissions
======================

.. autoclass:: rolca.rating.api.permissions.IsActiveJudge
    :members:

"""

from django.utils import timezone

from rest_framework import permissions

from rolca.rating.models import Judge


class CanModifyRating(permissions.BasePermission):
    """Keep published scores immutable and owned by their assigned judge."""

    def has_object_permission(self, request, view, obj):
        """Allow reads but restrict writes to active, matching judges."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return (
            obj.judge.judge_id == request.user.pk
            and obj.judge.contest.publish_date > timezone.now()
        )


class IsActiveJudge(permissions.BasePermission):
    """Allows access only to active judges."""

    def has_permission(self, request, view):
        """Return `True` if user active judge."""
        return (
            request.user.is_authenticated
            and Judge.objects.filter(
                judge=request.user, contest__publish_date__gte=timezone.now()
            ).exists()
        )
