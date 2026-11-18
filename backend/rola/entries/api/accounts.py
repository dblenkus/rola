"""Apply contest rules to the account endpoints.

``rola.accounts`` knows nothing about contests, so the rules that tie an account
to its entries live in the host project.
"""

from django.db.models import Q

from rola.accounts import views as user_views
from rola.entries.api.permissions import refuse_closed_entries
from rola.entries.models import Submission


class UserViewSet(user_views.UserViewSet):
    """Manage the current account, with administrative access for superusers."""

    def perform_destroy(self, instance):
        """Refuse to delete an account with entries in a closed contest.

        Deleting the account deletes its authors and submissions with their
        photographs, which judging and results still show.
        """
        refuse_closed_entries(
            Submission.objects.filter(Q(user=instance) | Q(author__user=instance))
        )
        super().perform_destroy(instance)
