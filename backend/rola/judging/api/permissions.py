"""Check who may judge a contest."""

from rest_framework import permissions

from rola.contests.models import Contest
from rola.judging.models import Judge


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
