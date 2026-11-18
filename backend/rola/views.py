"""Apply contest rules to the account endpoints.

``rola.accounts`` knows nothing about contests, so the rules that tie an account
to its entries live in the host project.
"""

from django.db.models import Q
from django.utils import timezone
from rest_framework import exceptions

from rola.accounts import views as user_views
from rola.contests.models import Submission


class UserViewSet(user_views.UserViewSet):
    """Manage the current account, with administrative access for superusers."""

    def perform_destroy(self, instance):
        """Refuse to delete an account with entries in a closed contest.

        Deleting the account deletes its authors and submissions with their
        photographs, which judging and results still show.
        """
        now = timezone.now()
        # Publishing the results closes the entries before the end date.
        closed = Submission.objects.filter(
            Q(user=instance) | Q(author__user=instance),
            Q(theme__contest__end_date__lt=now)
            | Q(theme__contest__publish_date__lte=now),
        )
        if closed.exists():
            raise exceptions.PermissionDenied(
                "Entries in a closed contest can no longer be changed."
            )
        super().perform_destroy(instance)
