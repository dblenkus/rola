"""Create and change submissions and their sets through the API."""

import logging
from datetime import timedelta
from smtplib import SMTPException
from unittest.mock import patch

import pytest
from django.utils import timezone

from rola.accounts.models import Email
from rola.contests.models import Contest, Theme
from rola.entries.models import Author, File, Submission, SubmissionSet
from tests.factories import (
    payload,
    photo,
    submitted,
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
        theme = Theme.objects.create(title="Second", contest=contest, max_photos=4)
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


@pytest.mark.parametrize("title", [None, ""])
def test_untitled_submission_has_a_name(world, title):
    item = submitted(world, title=title)
    assert str(item) == f"Submission {item.pk}"
