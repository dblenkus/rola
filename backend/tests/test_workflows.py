"""Regression tests for public APIs using the host's custom user contract."""

import io
import logging
import os
import queue
import tracemalloc
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from smtplib import SMTPException
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import CommandError, call_command
from django.db import connection, transaction
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from django.utils.text import slugify
from PIL import Image
from rest_framework.test import APIClient

from rola.accounts.models import Email, User
from rola.contests.models import Contest, Institution, Theme
from rola.entries.models import Author, File, Submission, SubmissionSet
from rola.judging.models import (
    AuthorReward,
    Judge,
    Rating,
    SubmissionReward,
    ThemeResults,
)
from rola.payments.models import Payment
from tests.factories import (
    PASSWORD,
    create_user,
    pay,
    payload,
    photo,
    submitted,
    wait_until_blocked_by_this_connection,
)

pytestmark = pytest.mark.django_db


def test_author_list_is_scoped_to_requesting_user(world):
    response = world.client.get("/api/v1/author")
    assert response.status_code == 200
    assert [item["id"] for item in response.data["results"]] == [world.author.pk]


@pytest.mark.parametrize("batch", [False, True])
def test_submission_creates_set_and_sends_one_confirmation_after_commit(
    world, batch, mailoutbox, django_capture_on_commit_callbacks
):
    world.contest.confirmation_email = Email.objects.create(
        subject="Thank you", body="Submitted"
    )
    world.contest.save()
    data = payload(world)
    if batch:
        data = [data, payload(world)]
    with django_capture_on_commit_callbacks(execute=True):
        response = world.client.post("/api/v1/submission", data, format="json")
        assert not mailoutbox
    assert response.status_code == 201, response.data
    assert isinstance(response.data, list) == batch
    group = SubmissionSet.objects.get()
    assert group.author == world.author
    assert group.contest == world.contest
    assert group.user == world.owner
    assert group.submissions.count() == (2 if batch else 1)
    assert len(mailoutbox) == 1
    assert mailoutbox[0].to == [world.owner.email]


def test_rejected_submission_sends_no_confirmation(
    world, mailoutbox, django_capture_on_commit_callbacks
):
    world.contest.confirmation_email = Email.objects.create(
        subject="Thank you", body="Submitted"
    )
    world.contest.save()
    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        response = world.client.post(
            "/api/v1/submission", payload(world, files=[{"id": 999999}]), format="json"
        )
    assert response.status_code == 400, response.data
    assert not callbacks
    assert not mailoutbox
    assert not Submission.objects.exists()


def test_confirmation_failure_keeps_the_committed_submission(
    world, caplog, django_capture_on_commit_callbacks
):
    world.contest.confirmation_email = Email.objects.create(
        subject="Thank you", body="Submitted"
    )
    world.contest.save()
    with (
        patch(
            "rola.accounts.models.send_mail", side_effect=SMTPException("unavailable")
        ),
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        response = world.client.post(
            "/api/v1/submission", payload(world), format="json"
        )
    assert response.status_code == 201, response.data
    assert len(callbacks) == 1
    assert SubmissionSet.objects.get().submissions.count() == 1
    assert [record.levelno for record in caplog.records] == [logging.ERROR]


@pytest.mark.parametrize(
    "case",
    [
        "empty",
        "unknown_author",
        "other_author",
        "unknown_file",
        "other_file",
        "duplicate_files",
        "attached_file",
        "mixed_contests",
        "mixed_authors",
        "reused_batch_file",
    ],
)
def test_invalid_submission_leaves_no_partial_records(world, case):
    data = payload(world)
    if case == "empty":
        data = []
    elif case == "unknown_author":
        data["author"] = {"id": 999999}
    elif case == "other_author":
        data["author"] = {"id": world.other_author.pk}
    elif case == "unknown_file":
        data["files"] = [{"id": 999999}]
    elif case == "other_file":
        data["files"] = [{"id": photo(world.other).pk}]
    elif case == "duplicate_files":
        data["files"] *= 2
    elif case == "attached_file":
        existing = submitted(world)
        File.objects.filter(pk=data["files"][0]["id"]).update(submission=existing)
    elif case == "mixed_contests":
        contest = Contest.objects.create(
            title="Second",
            start_date=world.contest.start_date,
            end_date=world.contest.end_date,
        )
        theme = Theme.objects.create(title="Second", contest=contest, n_photos=4)
        data = [data, payload(world, theme=theme.pk)]
    elif case == "mixed_authors":
        another = Author.objects.create(user=world.owner, first_name="Another")
        data = [data, payload(world, author={"id": another.pk})]
    elif case == "reused_batch_file":
        data = [data, dict(data)]
    before = Submission.objects.count()
    response = world.client.post("/api/v1/submission", data, format="json")
    assert response.status_code == 400, response.data
    assert Submission.objects.count() == before
    assert SubmissionSet.objects.count() == 0


def test_submission_database_failure_rolls_back_files_and_records(
    world, django_capture_on_commit_callbacks
):
    data = payload(world)
    with (
        django_capture_on_commit_callbacks(execute=True) as callbacks,
        patch(
            "rola.entries.services.SubmissionSet.objects.create",
            side_effect=RuntimeError("database failure"),
        ),
        pytest.raises(RuntimeError, match="database failure"),
    ):
        world.client.post("/api/v1/submission", data, format="json")
    assert not callbacks
    assert not Submission.objects.exists()
    assert File.objects.get(pk=data["files"][0]["id"]).submission_id is None


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_published_foreign_submission_cannot_be_modified(world, method):
    world.contest.publish_date = timezone.now() - timedelta(hours=1)
    world.contest.save()
    item = submitted(world, user=world.other, author=world.other_author)
    response = getattr(world.client, method)(
        f"/api/v1/submission/{item.pk}", {"title": "Changed"}, format="json"
    )
    assert response.status_code == 404
    item.refresh_from_db()
    assert item.title == "Original"
    assert item.user == world.other


def test_owner_can_patch_submission_and_replace_own_files(world):
    item = submitted(world)
    old = photo(world.owner)
    old.submission = item
    old.save()
    new = photo(world.owner)
    response = world.client.patch(
        f"/api/v1/submission/{item.pk}",
        {"title": "Edited", "files": [{"id": new.pk}]},
        format="json",
    )
    assert response.status_code == 200, response.data
    item.refresh_from_db()
    assert item.title == "Edited"
    assert item.user == world.owner
    assert list(item.files.values_list("pk", flat=True)) == [new.pk]
    assert not File.objects.filter(pk=old.pk).exists()


def test_submission_cannot_change_contest_or_author_after_grouping(world):
    response = world.client.post("/api/v1/submission", payload(world), format="json")
    assert response.status_code == 201
    author = Author.objects.create(user=world.owner, first_name="Another")
    response = world.client.patch(
        f"/api/v1/submission/{response.data['id']}",
        {"author": {"id": author.pk}},
        format="json",
    )
    assert response.status_code == 400


def test_owner_cannot_change_published_submission(world):
    item = submitted(world)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    assert (
        world.client.patch(
            f"/api/v1/submission/{item.pk}", {"title": "Late"}, format="json"
        ).status_code
        == 403
    )


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


def test_contest_and_institution_filters_are_applied(world):
    Contest.objects.create(
        title="Past",
        start_date=timezone.now() - timedelta(days=4),
        end_date=timezone.now() - timedelta(days=2),
    )
    response = world.client.get("/api/v1/contest", {"is_active": "true"})
    assert [item["id"] for item in response.data["results"]] == [world.contest.pk]
    desired = Institution.objects.create(kind=1, name="School")
    Institution.objects.create(kind=1, name="Elsewhere")
    response = world.client.get("/api/v1/institution", {"name": "School"})
    assert [item["id"] for item in response.data["results"]] == [desired.pk]


def test_submitted_contest_filter_lists_each_contest_once(world):
    for _ in range(3):
        submitted(world)
    other = Contest.objects.create(
        title="Other",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    other_theme = Theme.objects.create(contest=other, title="City", n_photos=4)
    submitted(world, user=world.other, author=world.other_author, theme=other_theme)
    response = world.client.get("/api/v1/contest", {"submitted": "true"})
    assert response.data["count"] == 1
    assert [item["id"] for item in response.data["results"]] == [world.contest.pk]
    response = world.client.get("/api/v1/contest", {"submitted": "false"})
    assert response.data["count"] == 1
    assert [item["id"] for item in response.data["results"]] == [other.pk]


def test_submission_and_set_filters_are_applied(world):
    item = submitted(world)
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(item)
    response = world.client.get("/api/v1/submission", {"contest": 999999})
    assert response.data["results"] == []
    other_contest = Contest.objects.create(
        title="Empty",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    response = world.client.get("/api/v1/submissionset", {"contest": other_contest.pk})
    assert response.data["results"] == []


def test_export_requires_organizer_and_includes_every_file(world):
    item = submitted(world)
    files = [photo(world.owner, "first.jpg"), photo(world.owner, "second.jpg")]
    item.files.add(*files)
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    staff = create_user("staff")
    staff.is_staff = True
    staff.save()
    world.client.force_login(staff)
    assert world.client.get(url).status_code == 403
    world.client.force_login(world.admin)
    response = world.client.get(url)
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.getvalue())) as archive:
        members = [name for name in archive.namelist() if not name.endswith("/")]
        assert len(members) == 2
        assert len(set(members)) == 2
        for name in members:
            assert Image.open(io.BytesIO(archive.read(name))).size == (800, 600)
            # Photographs carry the time of the download, in local time.
            written = datetime(*archive.getinfo(name).date_time)
            assert abs(written - datetime.now()) < timedelta(minutes=5)


def test_contest_admin_download_button_links_to_the_download(world):
    browser = Client()
    browser.force_login(world.admin)
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    for page in (
        "/django-admin/contests/contest/",
        f"/django-admin/contests/contest/{world.contest.pk}/change/",
    ):
        response = browser.get(page)
        assert response.status_code == 200
        assert f'<a class="button" href="{url}">Download</a>' in response.text


def test_export_sends_a_non_staff_organizer_to_the_admin_login(world):
    item = submitted(world)
    item.files.add(photo(world.owner))
    world.contest.user = world.owner
    world.contest.save()
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    browser = Client()
    browser.force_login(world.owner)
    response = browser.get(url)
    assert response.status_code == 302
    assert response.headers["Location"] == f"{reverse('admin:login')}?next={url}"


def test_export_sends_a_logged_out_organizer_to_the_admin_login(world):
    item = submitted(world)
    item.files.add(photo(world.owner))
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    browser = Client()
    response = browser.get(url)
    login_url = f"{reverse('admin:login')}?next={url}"
    assert response.status_code == 302
    assert response.headers["Location"] == login_url
    response = browser.post(
        login_url, {"username": world.admin.email, "password": PASSWORD, "next": url}
    )
    assert response.status_code == 302
    assert response.headers["Location"] == url
    response = browser.get(url)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/x-zip-compressed"


def test_export_builds_the_archive_without_holding_it_in_memory(world):
    noise = Image.frombytes("RGB", (1000, 1000), os.urandom(3_000_000))
    data = io.BytesIO()
    noise.save(data, "JPEG", quality=95)
    item = submitted(world)
    item.files.add(
        *[
            File.objects.create(
                user=world.owner,
                file=SimpleUploadedFile(
                    f"noise-{index}.jpg", data.getvalue(), content_type="image/jpeg"
                ),
            )
            for index in range(12)
        ]
    )
    world.client.force_login(world.admin)
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    # The first request imports and compiles modules, which tracing would count.
    world.client.get(url).getvalue()
    tracemalloc.start()
    try:
        response = world.client.get(url)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert response.status_code == 200
    size = int(response.headers["Content-Length"])
    assert size > 12 * len(data.getvalue())
    # An archive built in memory needs more than its own size.
    assert peak < size / 4
    assert response.headers["Content-Disposition"] == (
        f'attachment; filename="{slugify(world.contest.title)}.zip"'
    )
    content = response.getvalue()
    assert len(content) == size
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.testzip() is None
        assert len([name for name in archive.namelist() if name.endswith(".jpg")]) == 12


def test_export_command_writes_the_contest_archive(world, tmp_path):
    item = submitted(world)
    item.files.add(photo(world.owner, "first.jpg"), photo(world.owner, "second.jpg"))
    world.client.force_login(world.admin)
    response = world.client.get(
        f"/django-admin/contests/contest/{world.contest.pk}/download/"
    )
    assert response.status_code == 200
    exports = tmp_path / "exports"
    exports.mkdir()
    path = exports / "salon.zip"

    call_command("exportcontest", world.contest.pk, str(path))

    with (
        zipfile.ZipFile(io.BytesIO(response.getvalue())) as downloaded,
        zipfile.ZipFile(path) as exported,
    ):
        assert exported.testzip() is None
        assert exported.namelist() == downloaded.namelist()
        assert len([name for name in exported.namelist() if name.endswith(".jpg")]) == 2
        for name in downloaded.namelist():
            assert exported.read(name) == downloaded.read(name)

    # An existing file is neither overwritten nor removed.
    content = path.read_bytes()
    with pytest.raises(CommandError, match="already exists"):
        call_command("exportcontest", world.contest.pk, str(path))
    assert path.read_bytes() == content

    unknown = exports / "unknown.zip"
    with pytest.raises(CommandError, match="does not exist"):
        call_command("exportcontest", world.contest.pk + 1, str(unknown))
    assert not unknown.exists()

    # A photograph missing from storage fails the export without leaving part
    # of the archive behind.
    os.remove(item.files.first().file.path)
    failed = exports / "failed.zip"
    with pytest.raises(FileNotFoundError):
        call_command("exportcontest", world.contest.pk, str(failed))
    assert not failed.exists()


def test_payment_permissions_upsert_and_filter(world):
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    data = {"submissionset": group.pk, "paid": True}
    assert world.client.post("/api/v1/payment", data, format="json").status_code == 403
    world.client.force_authenticate(world.admin)
    assert world.client.post("/api/v1/payment", data, format="json").status_code == 201
    data["paid"] = False
    assert world.client.post("/api/v1/payment", data, format="json").status_code == 201
    assert Payment.objects.count() == 1
    assert not Payment.objects.get().paid
    assert world.client.get("/api/v1/payment", {"paid": "true"}).data["results"] == []


def test_judging_uses_postgres_ordering_and_scopes_paid_submissions(world):
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world, user=world.other, author=world.other_author)
    group = SubmissionSet.objects.create(
        user=world.other, author=world.other_author, contest=world.contest
    )
    group.submissions.add(item)
    Payment.objects.create(submissionset=group, paid=True)
    unpaid = submitted(world)
    response = world.client.get("/api/v1/judge/submission")
    assert response.status_code == 200, response.data
    assert [row["id"] for row in response.data["results"]] == [item.pk]
    other_theme = Theme.objects.create(contest=world.contest, title="Empty", n_photos=4)
    response = world.client.get("/api/v1/judge/submission", {"theme": other_theme.pk})
    assert response.data["results"] == []
    for value in [3, 5]:
        response = world.client.post(
            "/api/v1/rating", {"submission": item.pk, "rating": value}, format="json"
        )
        assert response.status_code == 201, response.data
    assert Rating.objects.get(judge=judge, submission=item).rating == 5
    response = world.client.get("/api/v1/rating", {"submission": unpaid.pk})
    assert response.data["results"] == []


def test_judges_see_submissions_without_their_authors(world):
    Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world, user=world.other, author=world.other_author)
    item.files.add(photo(world.other))
    group = SubmissionSet.objects.create(
        user=world.other, author=world.other_author, contest=world.contest
    )
    group.submissions.add(item)
    Payment.objects.create(submissionset=group, paid=True)
    response = world.client.get("/api/v1/judge/submission")
    assert response.status_code == 200, response.data
    [row] = response.json()["results"]
    assert set(row) == {
        "id",
        "created",
        "modified",
        "theme",
        "title",
        "description",
        "files",
    }
    assert [file["id"] for file in row["files"]] == [item.files.get().pk]


def test_anonymous_judge_endpoint_denies_without_server_error(world):
    response = APIClient().get("/api/v1/judge/submission")
    assert response.status_code == 401


def test_deleting_a_judge_answers_409(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    client = APIClient()
    client.force_authenticate(world.admin)

    response = client.delete(f"/api/v1/user/{world.other.id}")

    assert response.status_code == 409
    assert response.data["detail"] == (
        "This account cannot be deleted while other records depend on it."
    )
    assert User.objects.filter(pk=world.other.pk).exists()
    assert Judge.objects.filter(pk=judge.pk).exists()


def test_rating_updates_cannot_move_rating_to_another_contest(world):
    Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world)
    pay(item)
    response = world.client.post(
        "/api/v1/rating", {"submission": item.pk, "rating": 3}, format="json"
    )
    assert response.status_code == 201
    contest = Contest.objects.create(
        title="Other contest",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    theme = Theme.objects.create(contest=contest, title="Other", n_photos=4)
    other = submitted(world, theme=theme)
    pay(other)
    response = world.client.patch(
        f"/api/v1/rating/{response.data['id']}", {"submission": other.pk}, format="json"
    )
    assert response.status_code == 400


def test_ratings_of_unpaid_submissions_are_refused(world):
    Judge.objects.create(judge=world.owner, contest=world.contest)
    refused = {"submission": ["Only paid submissions can be rated."]}
    unpaid = submitted(world, user=world.other, author=world.other_author)
    response = world.client.post(
        "/api/v1/rating", {"submission": unpaid.pk, "rating": 5}, format="json"
    )
    assert response.status_code == 400
    assert response.data == refused
    assert not Rating.objects.exists()

    item = submitted(world, user=world.other, author=world.other_author)
    payment = pay(item)
    response = world.client.post(
        "/api/v1/rating", {"submission": item.pk, "rating": 5}, format="json"
    )
    assert response.status_code == 201, response.data
    rating = Rating.objects.get()
    payment.paid = False
    payment.save()
    revoked = [
        world.client.post(
            "/api/v1/rating", {"submission": item.pk, "rating": 9}, format="json"
        ),
        world.client.patch(f"/api/v1/rating/{rating.pk}", {"rating": 9}, format="json"),
    ]
    for response in revoked:
        assert response.status_code == 400
        assert response.data == refused
    rating.refresh_from_db()
    assert rating.rating == 5


@pytest.mark.parametrize("score", [0, 11, -1000])
def test_rating_scores_outside_1_to_10_are_refused(world, score):
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world)
    pay(item)
    response = world.client.post(
        "/api/v1/rating", {"submission": item.pk, "rating": score}, format="json"
    )
    assert response.status_code == 400
    assert set(response.data) == {"rating"}
    assert not Rating.objects.exists()

    rating = Rating.objects.create(
        judge=judge, user=world.owner, submission=item, rating=4
    )
    response = world.client.patch(
        f"/api/v1/rating/{rating.pk}", {"rating": score}, format="json"
    )
    assert response.status_code == 400
    assert set(response.data) == {"rating"}
    rating.refresh_from_db()
    assert rating.rating == 4


def test_results_hide_before_publication_and_handle_optional_relations(world):
    item = submitted(world)
    pay(item)
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    Rating.objects.create(user=world.other, judge=judge, submission=item, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    SubmissionReward.objects.create(submission=item, kind=1, label="Gold")
    public = APIClient()
    assert public.get("/api/v1/results/submission").data["results"] == []
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = public.get("/api/v1/results/submission")
    assert response.status_code == 200, response.data
    result = response.data["results"][0]
    assert result["accepted"] is True
    assert result["author"]["country"] is None
    assert result["author"]["reward"] is None
    assert result["author"]["reward_theme"] is None
    assert result["reward_kind"] == "Gold"


def test_published_theme_without_results_returns_not_found(world):
    submitted(world)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = APIClient().get(f"/api/v1/results/theme/{world.theme.pk}")
    assert response.status_code == 404
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    response = APIClient().get(f"/api/v1/results/theme/{world.theme.pk}")
    assert response.status_code == 200, response.data


def test_results_identify_the_rewarded_theme_by_id(world):
    item = submitted(world)
    pay(item)
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    Rating.objects.create(user=world.other, judge=judge, submission=item, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    AuthorReward.objects.create(
        author=world.author, theme=world.theme, label="Best author"
    )
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = APIClient().get("/api/v1/results/submission")
    assert response.status_code == 200, response.data
    author = response.json()["results"][0]["author"]
    assert author["reward"] == "Best author"
    assert author["reward_theme"] == world.theme.pk


@pytest.mark.parametrize("school_show", [False, True])
@pytest.mark.parametrize("club_show", [False, True])
def test_results_show_only_the_public_author_details(world, school_show, club_show):
    Author.objects.filter(pk=world.author.pk).update(
        email="alice@example.org",
        dob="2012-03-04",
        school="Primary school",
        mentor="Teacher Name",
        club="Photo club",
        distinction="Distinction",
    )
    accepted = submitted(world)
    pay(accepted)
    pay(submitted(world, title="Not accepted"))
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    Rating.objects.create(user=world.other, judge=judge, submission=accepted, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.school_show = school_show
    world.contest.club_show = club_show
    world.contest.save()
    public = APIClient()
    theme = public.get(f"/api/v1/results/theme/{world.theme.pk}").json()
    listing = public.get("/api/v1/results/submission").json()["results"]
    detail = public.get(f"/api/v1/results/submission/{accepted.pk}").json()
    authors = [row["author"] for row in theme["submissions"] + listing + [detail]]
    assert len(authors) == 4
    for author in authors:
        assert author == {
            "id": world.author.pk,
            "first_name": "Alice",
            "last_name": "Photographer",
            "school": "Primary school" if school_show else None,
            "club": "Photo club" if club_show else None,
            "country": None,
            "reward": None,
            "reward_theme": None,
        }


def test_theme_results_list_only_paid_entries_without_scores(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    accepted = submitted(world, title="Accepted")
    declined = submitted(world, title="Declined")
    unpaid = submitted(world, title="Unpaid")
    submitted(world, user=world.other, author=world.other_author, title="Unjudged")
    pay(accepted)
    # A second paid set must neither repeat the entry nor add its score twice,
    # which would lift 2 over the threshold of 3.
    pay(declined)
    pay(declined)
    payment = pay(unpaid)
    payment.paid = False
    payment.save()
    for item, score in [(accepted, 5), (declined, 2), (unpaid, 5)]:
        Rating.objects.create(
            user=world.other, judge=judge, submission=item, rating=score
        )
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()

    response = APIClient().get(f"/api/v1/results/theme/{world.theme.pk}")
    assert response.status_code == 200, response.data
    theme = response.json()
    assert [(row["id"], row["accepted"]) for row in theme["submissions"]] == [
        (accepted.pk, True),
        (declined.pk, False),
    ]
    assert theme["submissions_number"] == 2
    for row in theme["submissions"]:
        assert "rating" not in row


def test_submission_results_list_only_paid_entries(world):
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    paid = submitted(world, title="Paid")
    unpaid = submitted(world, title="Unpaid")
    # A second paid set must neither repeat the entry nor add its score twice.
    pay(paid)
    pay(paid)
    for item in [paid, unpaid]:
        Rating.objects.create(user=world.other, judge=judge, submission=item, rating=5)
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    public = APIClient()

    response = public.get("/api/v1/results/submission")
    assert response.status_code == 200, response.data
    assert [(row["id"], row["rating"]) for row in response.data["results"]] == [
        (paid.pk, 5)
    ]
    assert public.get(f"/api/v1/results/submission/{paid.pk}").status_code == 200
    assert public.get(f"/api/v1/results/submission/{unpaid.pk}").status_code == 404


def test_published_submissions_stay_private_to_their_owner(world):
    item = submitted(world)
    item.files.add(photo(world.owner))
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    for account in [world.other, world.admin]:
        world.client.force_authenticate(account)
        assert world.client.get("/api/v1/submission").data["results"] == []
        response = world.client.get(f"/api/v1/submission/{item.pk}")
        assert response.status_code == 404
    world.client.force_authenticate(world.owner)
    response = world.client.get("/api/v1/submission")
    assert [row["id"] for row in response.data["results"]] == [item.pk]


@pytest.mark.parametrize("method", ["patch", "delete"])
def test_published_scores_are_immutable(world, method):
    judge = Judge.objects.create(judge=world.owner, contest=world.contest)
    item = submitted(world)
    pay(item)
    rating = Rating.objects.create(
        judge=judge, user=world.owner, submission=item, rating=4
    )
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    response = getattr(world.client, method)(
        f"/api/v1/rating/{rating.pk}", {"rating": 1}, format="json"
    )
    assert response.status_code == 403
    rating.refresh_from_db()
    assert rating.rating == 4


def test_the_api_answers_only_json(world):
    submitted(world, title="Unpublished entry")
    world.client.force_authenticate(world.other)
    browsable = world.client.get("/api/v1/rating?format=api")
    assert browsable.status_code == 404
    html = world.client.get("/api/v1/rating", HTTP_ACCEPT="text/html")
    assert html.status_code == 406
    for response in [browsable, html]:
        assert response["Content-Type"] == "application/json"
        assert b"Unpublished entry" not in response.content


@pytest.mark.parametrize("title", [None, ""])
def test_untitled_submission_has_a_name(world, title):
    item = submitted(world, title=title)
    assert str(item) == f"Submission {item.pk}"
