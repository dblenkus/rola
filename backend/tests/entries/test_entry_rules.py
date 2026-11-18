"""Accept entries only while the contest is open, within each theme's photo limit, and once per upload."""

import queue
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from django.db import connection, transaction
from django.utils import timezone
from rest_framework.test import APIClient

from rola.accounts.models import Email
from rola.contests.models import Theme
from rola.entries.models import Author, File, Submission, SubmissionSet
from tests.factories import (
    payload,
    photo,
    submitted,
    wait_until_blocked_by_this_connection,
)

pytestmark = pytest.mark.django_db


# Start, end and publication of a contest that accepts no entries, from now.
CLOSED_SCHEDULES = {
    "before_start": (timedelta(hours=1), timedelta(days=1), timedelta(days=2)),
    "after_end": (-timedelta(days=2), -timedelta(hours=1), timedelta(days=1)),
    "after_publication": (
        -timedelta(days=3),
        -timedelta(days=2),
        -timedelta(hours=1),
    ),
    "published_before_end": (
        -timedelta(days=1),
        timedelta(days=1),
        -timedelta(hours=1),
    ),
}
ENTRIES_CLOSED = {"detail": "This contest is not accepting entries."}


def reschedule(contest, start, end, publish):
    """Move the contest's start, end and publication relative to now."""
    now = timezone.now()
    contest.start_date = now + start
    contest.end_date = now + end
    contest.publish_date = now + publish
    contest.save()


def entered(world):
    """Enter a submission with one photograph as a submission set."""
    item = submitted(world)
    item.files.add(photo(world.owner))
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(item)
    return item, group


@pytest.mark.parametrize("schedule", list(CLOSED_SCHEDULES))
@pytest.mark.parametrize("batch", [False, True])
def test_entries_are_accepted_only_while_the_contest_is_open(world, schedule, batch):
    reschedule(world.contest, *CLOSED_SCHEDULES[schedule])
    data = [payload(world), payload(world)] if batch else payload(world)
    response = world.client.post("/api/v1/submission", data, format="json")
    assert response.status_code == 403
    assert response.json() == ENTRIES_CLOSED
    assert not Submission.objects.exists()
    assert not SubmissionSet.objects.exists()
    assert not File.objects.filter(submission__isnull=False).exists()


@pytest.mark.parametrize(
    ("method", "endpoint"),
    [
        ("put", "submission"),
        ("patch", "submission"),
        ("delete", "submission"),
        ("delete", "submissionset"),
    ],
)
def test_entries_cannot_change_after_the_contest_closes(world, method, endpoint):
    item, group = entered(world)
    image = item.files.get()
    reschedule(world.contest, *CLOSED_SCHEDULES["after_end"])
    target = item if endpoint == "submission" else group
    data = payload(world, title="Late") if method != "delete" else None
    response = getattr(world.client, method)(
        f"/api/v1/{endpoint}/{target.pk}", data, format="json"
    )
    assert response.status_code == 403
    assert response.json() == ENTRIES_CLOSED
    item.refresh_from_db()
    assert item.title == "Original"
    assert list(item.files.all()) == [image]
    assert list(group.submissions.all()) == [item]


def test_superusers_delete_submission_sets_until_publication(world):
    (judged, judged_set), (published, published_set) = entered(world), entered(world)
    reschedule(world.contest, *CLOSED_SCHEDULES["after_end"])
    world.client.force_authenticate(world.admin)
    response = world.client.delete(f"/api/v1/submissionset/{judged_set.pk}")
    assert response.status_code == 204
    assert not Submission.objects.filter(pk=judged.pk).exists()

    reschedule(world.contest, *CLOSED_SCHEDULES["after_publication"])
    response = world.client.delete(f"/api/v1/submissionset/{published_set.pk}")
    assert response.status_code == 403
    assert response.json() == ENTRIES_CLOSED
    assert list(published_set.submissions.all()) == [published]


def test_a_theme_accepts_at_most_n_photos_per_author(world):
    world.theme.n_photos = 2
    world.theme.save()
    city = Theme.objects.create(contest=world.contest, title="City", n_photos=1)
    series = Theme.objects.create(
        contest=world.contest, title="Series", is_series=True, n_photos=3
    )

    def post(data):
        return world.client.post("/api/v1/submission", data, format="json")

    def photos(count):
        return [{"id": photo(world.owner).pk} for _ in range(count)]

    response = post([payload(world) for _ in range(3)])
    assert response.status_code == 400
    assert response.json() == {
        "files": [
            'Too many photographs for the theme "Nature", which accepts 2 per author.'
        ]
    }
    assert not Submission.objects.exists()

    first, _ = post([payload(world), payload(world)]).data
    assert post(payload(world)).status_code == 400
    another = Author.objects.create(user=world.owner, first_name="Another")
    assert post(payload(world, author={"id": another.pk})).status_code == 201
    assert post(payload(world, theme=city.pk)).status_code == 201
    assert Submission.objects.filter(author=world.author).count() == 3

    url = f"/api/v1/submission/{first['id']}"
    replaced = world.client.patch(url, {"files": photos(1)}, format="json")
    assert replaced.status_code == 200, replaced.data
    added = world.client.patch(url, {"files": photos(2)}, format="json")
    assert added.status_code == 400
    moved = world.client.patch(url, {"theme": city.pk}, format="json")
    assert moved.status_code == 400
    assert Submission.objects.get(pk=first["id"]).theme == world.theme
    assert File.objects.filter(submission=first["id"]).count() == 1

    assert post(payload(world, theme=series.pk, files=photos(4))).status_code == 400
    assert post(payload(world, theme=series.pk, files=photos(3))).status_code == 201
    assert post(payload(world, theme=series.pk, files=photos(1))).status_code == 400
    assert File.objects.filter(submission__theme=series).count() == 3


def test_a_repeated_upload_returns_the_existing_set(
    world, mailoutbox, django_capture_on_commit_callbacks
):
    world.contest.confirmation_email = Email.objects.create(
        subject="Thank you", body="Submitted"
    )
    world.contest.save()
    key = str(uuid.uuid4())
    other_client = APIClient()
    other_client.force_authenticate(world.other)

    def upload(data, key, client=world.client):
        with django_capture_on_commit_callbacks(execute=True):
            return client.post(
                "/api/v1/submission", data, format="json", HTTP_IDEMPOTENCY_KEY=key
            )

    batch = [payload(world), payload(world)]
    first = upload(batch, key)
    assert first.status_code == 201, first.data
    # A retry after a lost response uploads its photographs again.
    retry = upload([payload(world), payload(world)], key)
    assert retry.status_code == 200, retry.data
    assert retry.json() == first.json()

    assert upload([payload(world)], str(uuid.uuid4())).status_code == 201
    foreign = payload(
        world,
        author={"id": world.other_author.pk},
        files=[{"id": photo(world.other).pk}],
    )
    assert upload([foreign], key, other_client).status_code == 201
    refused = upload([payload(world)], "not-a-uuid")
    assert refused.status_code == 400
    assert refused.json() == {"detail": "The Idempotency-Key header must be a UUID."}

    # The repeated request would now be refused: its photographs are
    # attached and the contest has closed.
    reschedule(world.contest, *CLOSED_SCHEDULES["after_end"])
    late = upload(batch, key)
    assert late.status_code == 200, late.data
    assert late.json() == first.json()
    single = upload(batch[0], key)
    assert single.status_code == 200, single.data
    assert single.json() == first.json()[0]

    assert SubmissionSet.objects.filter(user=world.owner).count() == 2
    assert SubmissionSet.objects.filter(user=world.other).count() == 1
    assert Submission.objects.count() == 4
    assert [message.to for message in mailoutbox] == [
        [world.owner.email],
        [world.owner.email],
        [world.other.email],
    ]


@pytest.mark.parametrize("batch", [False, True])
def test_a_repeated_upload_is_entered_again_after_its_submissions_are_deleted(
    world, batch, mailoutbox, django_capture_on_commit_callbacks
):
    world.contest.confirmation_email = Email.objects.create(
        subject="Thank you", body="Submitted"
    )
    world.contest.save()
    key = str(uuid.uuid4())

    def upload():
        data = payload(world)
        with django_capture_on_commit_callbacks(execute=True):
            response = world.client.post(
                "/api/v1/submission",
                [data] if batch else data,
                format="json",
                HTTP_IDEMPOTENCY_KEY=key,
            )
        assert isinstance(response.json(), list) == batch
        return response

    def entered(response):
        items = response.json() if batch else [response.json()]
        return [item["id"] for item in items]

    first = upload()
    assert first.status_code == 201, first.data
    (deleted,) = entered(first)
    response = world.client.delete(f"/api/v1/submission/{deleted}")
    assert response.status_code == 204
    # The upload form keeps its key until it is completed, so a retry after
    # a lost response can follow the deletion of the entry.
    retry = upload()
    assert retry.status_code == 201, retry.data
    assert list(
        SubmissionSet.objects.get(upload_key=key).submissions.values_list(
            "pk", flat=True
        )
    ) == entered(retry)
    replay = upload()
    assert replay.status_code == 200, replay.data
    assert replay.json() == retry.json()

    assert SubmissionSet.objects.filter(user=world.owner).count() == 2
    assert Submission.objects.count() == 1
    assert [message.to for message in mailoutbox] == [
        [world.owner.email],
        [world.owner.email],
    ]


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_concurrent_uploads_with_one_key_create_one_set(world, mailoutbox):
    world.contest.confirmation_email = Email.objects.create(
        subject="Thank you", body="Submitted"
    )
    world.contest.save()
    key = str(uuid.uuid4())
    first_data, retry_data = [payload(world)], [payload(world)]
    retry_client = APIClient()
    retry_client.force_authenticate(world.owner)
    backend_pids = queue.SimpleQueue()

    def upload(client, data):
        return client.post(
            "/api/v1/submission", data, format="json", HTTP_IDEMPOTENCY_KEY=key
        )

    def retry_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return upload(retry_client, retry_data)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            first = upload(world.client, first_data)
            retry = executor.submit(retry_on_another_connection)
            # The retry waits for the first upload's lock on the account row
            # and then finds the committed set.
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        second = retry.result(timeout=10)

    assert first.status_code == 201, first.data
    assert second.status_code == 200, second.data
    assert second.json() == first.json()
    assert SubmissionSet.objects.count() == 1
    assert len(mailoutbox) == 1


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_an_upload_deleted_during_a_submission_answers_a_files_error(world):
    image = photo(world.owner)
    data = payload(world, files=[{"id": image.pk}])
    client = APIClient()
    client.force_authenticate(world.owner)
    backend_pids = queue.SimpleQueue()

    def submit_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return client.post("/api/v1/submission", data, format="json")
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            File.objects.select_for_update().get(pk=image.pk)
            submission = executor.submit(submit_on_another_connection)
            # The submission has validated the upload, waits for its row lock
            # and then finds it deleted.
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
            File.objects.filter(pk=image.pk).delete()
        response = submission.result(timeout=10)

    assert response.status_code == 400
    assert response.json() == {"files": ["An upload is no longer available."]}
    assert not Submission.objects.exists()
