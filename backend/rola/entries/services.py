"""Enter and change submissions under the contest's rules.

:func:`require_open_contest` and :func:`refuse_closed_entries` check a
contest's dates and may run anywhere. Every other function here expects to
run inside the caller's transaction, after :func:`lock_account` has locked
the requester's account. The rules raise the REST framework's exceptions, so
the API answers with their payloads.
"""

import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from functools import partial
from typing import Any

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import QuerySet
from rest_framework import exceptions

from rola.accounts.models import User
from rola.contests.models import Contest, Theme
from rola.entries.models import Author, File, Submission, SubmissionSet


def require_open_contest(contest: Contest) -> None:
    """Answer 403 unless the contest accepts entries.

    :raises PermissionDenied: If the contest does not accept entries now.
    """
    if not contest.accepts_entries():
        raise exceptions.PermissionDenied("This contest is not accepting entries.")


def refuse_closed_entries(submissions: QuerySet[Submission]) -> None:
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


def lock_account(user: User) -> None:
    """Serialize the account's submission writes.

    Concurrent writes would otherwise each count the photographs in a
    theme without the ones that the other is adding.
    """
    get_user_model().objects.select_for_update().get(pk=user.pk)


def find_upload(user: User, upload_key: uuid.UUID) -> SubmissionSet | None:
    """Return the submission set of the user's earlier upload with the key.

    Deleting submissions keeps their set, which a payment may refer to, so
    an empty set means the earlier upload was withdrawn: the key is
    released for a new upload and ``None`` is returned.

    :param user: The account that uploads.
    :param upload_key: The upload's Idempotency-Key.
    :return: The earlier upload's set, or ``None`` if there is none to repeat.
    """
    uploaded = SubmissionSet.objects.filter(user=user, upload_key=upload_key).first()
    if uploaded is not None and not uploaded.submissions.exists():
        SubmissionSet.objects.filter(pk=uploaded.pk).update(upload_key=None)
        return None
    return uploaded


def enter_submissions(
    user: User,
    items: Sequence[Mapping[str, Any]],
    upload_key: uuid.UUID | None,
) -> list[Submission]:
    """Create the submissions of one upload and the submission set that holds them.

    The submissions must belong to one contest that accepts entries and to
    one author, may use each file once, and may not take a theme past its
    number of photographs per author. The contest's confirmation email is
    sent once the transaction commits.

    :param user: The account that uploads, already locked.
    :param items: The validated submissions, each with its ``files``.
    :param upload_key: The upload's Idempotency-Key, or ``None`` without one.
    :return: The created submissions, in the order of ``items``.
    :raises ValidationError: If the submissions break one of these rules.
    :raises PermissionDenied: If the contest does not accept entries.
    """
    contest = items[0]["theme"].contest
    if any(item["theme"].contest_id != contest.pk for item in items):
        raise exceptions.ValidationError(
            "All submissions must belong to the same contest."
        )
    require_open_contest(contest)
    if any(item["author"] != items[0]["author"] for item in items):
        raise exceptions.ValidationError("All submissions must have the same author.")
    files = [file for item in items for file in item["files"]]
    if len({file.pk for file in files}) != len(files):
        raise exceptions.ValidationError(
            "Each file may only be used once in a submission set."
        )
    new_photos: Counter[Theme] = Counter()
    for item in items:
        new_photos[item["theme"]] += len(item["files"])
    for theme, count in new_photos.items():
        limit_photos(items[0]["author"], theme, count)
    lock_files(user, files)

    submissions = []
    for item in items:
        fields = {name: value for name, value in item.items() if name != "files"}
        submission = Submission.objects.create(**fields)
        submission.files.add(*item["files"])
        submissions.append(submission)

    submission_set = SubmissionSet.objects.create(
        author=submissions[0].author,
        user=submissions[0].user,
        contest=contest,
        upload_key=upload_key,
    )
    submission_set.submissions.add(*submissions)

    if contest.confirmation_email and user.email:
        transaction.on_commit(
            partial(contest.confirmation_email.send, user.email), robust=True
        )
    return submissions


def limit_photos(
    author: Author, theme: Theme, count: int, submission: Submission | None = None
) -> None:
    """Refuse more than the theme's number of photographs per author.

    The limit counts photographs, not submissions: a series is one
    submission with up to that many photographs.

    :param author: The author of the photographs.
    :param theme: The theme that the photographs are entered in.
    :param count: The number of photographs to enter.
    :param submission: The submission whose photographs ``count`` replaces.
    :raises ValidationError: If the theme would hold too many photographs.
    """
    entered = File.objects.filter(submission__author=author, submission__theme=theme)
    if submission is not None:
        entered = entered.exclude(submission=submission)
    if entered.count() + count > theme.max_photos:
        raise exceptions.ValidationError(
            {
                "files": [
                    f'Too many photographs for the theme "{theme.title}", '
                    f"which accepts {theme.max_photos} per author."
                ]
            }
        )


def lock_files(
    user: User, files: Iterable[File], submission: int | None = None
) -> None:
    """Recheck attachment state under a lock to prevent concurrent file reuse.

    :param user: The account that must own the files.
    :param files: The files to attach.
    :param submission: The id of the submission that may already hold them.
    :raises ValidationError: If a file is gone, someone else's, or attached
        to another submission.
    """
    files = list(files)
    locked = list(
        File.objects.select_for_update()
        .filter(pk__in=[file.pk for file in files])
        .order_by("pk")
    )
    if len(locked) != len(files) or any(
        file.user_id != user.pk or file.submission_id not in (None, submission)
        for file in locked
    ):
        raise exceptions.ValidationError(
            {"files": ["An upload is no longer available."]}
        )
