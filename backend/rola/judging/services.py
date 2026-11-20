"""Set and clear the judges' ratings of submissions under the judging rules.

The rules raise the REST framework's exceptions, so the API answers with
their payloads.
"""

import contextlib

from rest_framework import exceptions

from rola.accounts.models import User
from rola.contests.models import Contest
from rola.entries.models import Submission
from rola.judging.models import Judge, Rating
from rola.payments.models import PAID_SUBMISSION


def set_rating(user: User, submission_id: int, rating: int) -> tuple[Rating, bool]:
    """Set the judge's rating of a submission, creating the rating if there is none.

    The account must be a judge of the submission's contest, the submission
    must be in a paid submission set, as the judging list shows, and the
    contest's results must not be published yet. A created rating records the
    account and its judge of the contest; an update changes only the score.
    Of two concurrent first calls for one submission, the later one waits for
    the earlier one's rating and updates it.

    :param user: The account that rates.
    :param submission_id: The id of the submission to rate.
    :param rating: The score, from 1 to 10.
    :return: The rating, and whether it was created.
    :raises NotFound: If the submission does not exist, the account is not a
        judge of its contest, or it is not paid. The three answer alike, so
        the answer does not reveal which submissions exist or are paid.
    :raises PermissionDenied: If the contest's results are published.
    """
    judge = _rating_judge(user, submission_id)
    # update_or_create locks the rating row in its own transaction and, when
    # a concurrent insert wins the unique constraint, reads that row.
    return Rating.objects.update_or_create(
        judge=judge,
        submission_id=submission_id,
        defaults={"rating": rating},
        create_defaults={"rating": rating, "user": user},
    )


def clear_rating(user: User, submission_id: int) -> None:
    """Delete the judge's rating of a submission, if there is one.

    The rules are those of :func:`set_rating`. Only the rating of the
    account's own judge of the contest is deleted, and clearing a submission
    that the judge has not rated succeeds as well, so a repeated call
    changes nothing.

    :param user: The account that rates.
    :param submission_id: The id of the submission whose rating to clear.
    :raises NotFound: If the submission does not exist, the account is not a
        judge of its contest, or it is not paid. The three answer alike, so
        the answer does not reveal which submissions exist or are paid.
    :raises PermissionDenied: If the contest's results are published.
    """
    judge = _rating_judge(user, submission_id)
    Rating.objects.filter(judge=judge, submission_id=submission_id).delete()


def _rating_judge(user: User, submission_id: int) -> Judge:
    """Return the account's judge that may rate a submission.

    :param user: The account that rates.
    :param submission_id: The id of the submission to rate.
    :return: The account's judge of the submission's contest.
    :raises NotFound: If the submission does not exist, the account is not a
        judge of its contest, or it is not paid. The three answer alike, so
        the answer does not reveal which submissions exist or are paid.
    :raises PermissionDenied: If the contest's results are published.
    """
    judge = None
    with contextlib.suppress(Judge.DoesNotExist):
        judge = Judge.objects.get(judge=user, contest__themes__submission=submission_id)
    if (
        judge is None
        or not Submission.objects.filter(PAID_SUBMISSION, pk=submission_id).exists()
    ):
        raise exceptions.NotFound(
            "There is no submission with this id that you can rate."
        )
    if not Contest.objects.results_unpublished().filter(pk=judge.contest_id).exists():
        raise exceptions.PermissionDenied(
            "The results of this contest are published, so its ratings are final."
        )
    return judge
