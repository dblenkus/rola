"""Keep ratings unique per judge and submission and in range in the database."""

import queue
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection, transaction
from django.utils import timezone

from rolca.core.models import Author, Contest, Submission, Theme
from rolca.rating.models import Judge, Rating


def create_judge_and_submission():
    """Create a contest judge and a submission they can rate."""
    user = get_user_model().objects.create_user(email="judge@example.com")
    now = timezone.now()
    contest = Contest.objects.create(
        title="Salon",
        start_date=now - timedelta(days=2),
        end_date=now - timedelta(days=1),
        publish_date=now + timedelta(days=1),
    )
    theme = Theme.objects.create(contest=contest, title="Nature", n_photos=4)
    author = Author.objects.create(first_name="Alice", last_name="Photographer")
    submission = Submission.objects.create(author=author, theme=theme)
    return Judge.objects.create(contest=contest, judge=user), submission


@pytest.mark.django_db
def test_a_judge_rates_a_submission_once():
    judge, submission = create_judge_and_submission()
    Rating.objects.create(judge=judge, submission=submission, rating=5)

    with pytest.raises(IntegrityError), transaction.atomic():
        Rating.objects.create(judge=judge, submission=submission, rating=7)
    assert list(Rating.objects.values_list("rating", flat=True)) == [5]


@pytest.mark.django_db
@pytest.mark.parametrize("score", [0, 11])
def test_a_rating_score_is_between_1_and_10(score):
    judge, submission = create_judge_and_submission()

    with pytest.raises(IntegrityError), transaction.atomic():
        Rating.objects.create(judge=judge, submission=submission, rating=score)
    assert not Rating.objects.exists()


def wait_until_blocked_by_this_connection(pid):
    """Wait until database backend ``pid`` waits for a lock this connection holds."""
    deadline = time.monotonic() + 10
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_backend_pid()")
        (own_pid,) = cursor.fetchone()
        while True:
            cursor.execute("SELECT pg_blocking_pids(%s)", [pid])
            if own_pid in cursor.fetchone()[0]:
                return
            if time.monotonic() > deadline:
                pytest.fail("The second rating never waited for the first one.")
            time.sleep(0.01)


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_concurrent_first_ratings_keep_one_row():
    # update_or_create locks an existing row, but the first rating has none
    # to lock. Only the unique index makes the second insert wait and then
    # update the committed row instead of adding another one.
    judge, submission = create_judge_and_submission()
    backend_pids = queue.SimpleQueue()

    def rate_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return Rating.objects.update_or_create(
                judge=judge, submission=submission, defaults={"rating": 7}
            )
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            Rating.objects.update_or_create(
                judge=judge, submission=submission, defaults={"rating": 5}
            )
            second = executor.submit(rate_on_another_connection)
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        _, created = second.result(timeout=10)

    assert not created
    assert list(Rating.objects.values_list("rating", flat=True)) == [7]
