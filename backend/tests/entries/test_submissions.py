"""Enter submissions and their sets through the API, and list and delete them."""

import logging
from datetime import timedelta
from smtplib import SMTPException
from unittest.mock import patch

import pytest
from django.utils import timezone

from rola.accounts.models import Email
from rola.contests.models import Contest
from rola.entries.models import File, Submission, SubmissionSet
from tests.factories import entry, payload, submitted

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("count", [1, 2])
def test_submission_creates_set_and_sends_one_confirmation_after_commit(
    world, count, mailoutbox, django_capture_on_commit_callbacks
):
    world.contest.confirmation_email = Email.objects.create(
        subject="Thank you", body="Submitted"
    )
    world.contest.save()
    data = payload(world, *(entry(world) for _ in range(count)))
    with django_capture_on_commit_callbacks(execute=True):
        response = world.client.post("/api/v1/submission-sets", data, format="json")
        assert not mailoutbox
    assert response.status_code == 201, response.data
    assert len(response.data["submissions"]) == count
    group = SubmissionSet.objects.get()
    assert group.author == world.author
    assert group.contest == world.contest
    assert group.user == world.owner
    assert group.submissions.count() == count
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
            "/api/v1/submission-sets",
            payload(world, entry(world, files=[999999])),
            format="json",
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
            "/api/v1/submission-sets", payload(world), format="json"
        )
    assert response.status_code == 201, response.data
    assert len(callbacks) == 1
    assert SubmissionSet.objects.get().submissions.count() == 1
    assert [record.levelno for record in caplog.records] == [logging.ERROR]


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
        world.client.post("/api/v1/submission-sets", data, format="json")
    assert not callbacks
    assert not Submission.objects.exists()
    (image,) = data["submissions"][0]["files"]
    assert File.objects.get(pk=image).submission_id is None


def test_published_foreign_submission_cannot_be_deleted(world):
    world.contest.publish_date = timezone.now() - timedelta(hours=1)
    world.contest.save()
    item = submitted(world, user=world.other, author=world.other_author)
    response = world.client.delete(f"/api/v1/submissions/{item.pk}")
    assert response.status_code == 404
    item.refresh_from_db()
    assert item.title == "Original"
    assert item.user == world.other


def test_submission_and_set_filters_are_applied(world):
    item = submitted(world)
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(item)
    response = world.client.get("/api/v1/submissions", {"contest": 999999})
    assert response.data["results"] == []
    other_contest = Contest.objects.create(
        title="Empty",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    response = world.client.get(
        "/api/v1/submission-sets", {"contest": other_contest.pk}
    )
    assert response.data["results"] == []


@pytest.mark.parametrize("title", [None, ""])
def test_untitled_submission_has_a_name(world, title):
    item = submitted(world, title=title)
    assert str(item) == f"Submission {item.pk}"
