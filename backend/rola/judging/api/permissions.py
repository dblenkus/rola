"""Check who may judge a contest and change a rating."""

from rest_framework import permissions

from rola.contests.models import Contest
from rola.judging.models import Judge


class CanModifyRating(permissions.BasePermission):
    """Keep published scores immutable and owned by their assigned judge."""

    def has_object_permission(self, request, view, obj):
        """Allow reads but restrict writes to active, matching judges."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return (
            obj.judge.judge_id == request.user.pk
            and not obj.judge.contest.results_published()
        )


class IsActiveJudge(permissions.BasePermission):
    """Allows access only to active judges."""

    def has_permission(self, request, view):
        """Return `True` if user active judge."""
        return (
            request.user.is_authenticated
            and Judge.objects.filter(
                judge=request.user, contest__in=Contest.objects.in_judging()
            ).exists()
        )
