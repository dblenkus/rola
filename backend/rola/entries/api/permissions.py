"""Check who may change entries and when."""

from rest_framework import exceptions, permissions

from rola.contests.models import Contest


def require_open_contest(contest: Contest) -> None:
    """Answer 403 unless the contest accepts entries.

    :raises PermissionDenied: If the contest does not accept entries now.
    """
    if not contest.accepts_entries():
        raise exceptions.PermissionDenied("This contest is not accepting entries.")


def refuse_closed_entries(submissions):
    """Answer 403 if any of the submissions is in a closed contest.

    Judging and results show the entries of a closed contest, so they stay
    as they are.

    :param submissions: The submissions that the request would change or delete.
    :raises PermissionDenied: If a submission's contest is closed.
    """
    if submissions.filter(theme__contest__in=Contest.objects.closed()).exists():
        raise exceptions.PermissionDenied(
            "Entries in a closed contest can no longer be changed."
        )


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
