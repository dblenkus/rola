"""Build accounts, photographs and submissions, and share helpers between tests."""

import io
import time

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.urls import reverse
from django.utils import timezone
from PIL import Image
from rest_framework.test import APIClient

from rola.accounts.models import Token, User
from rola.contests.models import Contest
from rola.entries.models import Author, File, Submission, SubmissionSet
from rola.payments.models import Payment

PASSWORD = "test-only-passphrase-A9!"


def create_user(name, *, superuser=False):
    """Create an active account with the address ``<name>@example.org``."""
    create = User.objects.create_superuser if superuser else User.objects.create_user
    return create(f"{name}@example.org", PASSWORD, is_active=True)


def client_sending(authorization):
    """Send the given ``Authorization`` header with every API call."""
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=authorization)
    return client


def bearer_client(key):
    """Send the given login token string as a Bearer token with every API call."""
    return client_sending(f"Bearer {key}")


def logged_in_client(user):
    """Authenticate API calls with a new login token of the given account."""
    return bearer_client(Token.objects.create_token(user=user).key)


def mark_account(user, first_name="Own"):
    """Give the account one submission set by an author of the given first name.

    Only the account's own credentials list the set, so
    :func:`marked_authors` tells which account a credential belongs to.
    """
    now = timezone.now()
    contest = Contest.objects.create(
        user=user, title="Marker", start_date=now, end_date=now, publish_date=now
    )
    author = Author.objects.create(user=user, first_name=first_name)
    return SubmissionSet.objects.create(user=user, author=author, contest=contest)


def marked_authors(client):
    """List the first names of the set authors that the API shows the caller."""
    response = client.get(reverse("submission-set-list"))
    assert response.status_code == 200
    return [result["author"]["first_name"] for result in response.data["results"]]


def photo(user, name="photo.jpg"):
    """Create a stored JPEG belonging to the given account."""
    data = io.BytesIO()
    Image.new("RGB", (800, 600), "red").save(data, "JPEG")
    return File.objects.create(
        user=user,
        file=SimpleUploadedFile(name, data.getvalue(), content_type="image/jpeg"),
    )


def entry(world, **changes):
    """Build one submission of an upload, with a photograph owned by the submitter."""
    result = {
        "title": "Photo",
        "theme": world.theme.pk,
        "files": [photo(world.owner).pk],
    }
    result.update(changes)
    return result


def payload(world, *entries, author=None):
    """Build an upload request of the given submissions, or of one by default."""
    return {
        "author": (author or world.author).pk,
        "submissions": list(entries) if entries else [entry(world)],
    }


def submitted(world, **changes):
    """Create a submission in the fixture contest."""
    data = dict(
        user=world.owner, title="Original", theme=world.theme, author=world.author
    )
    data.update(changes)
    return Submission.objects.create(**data)


def pay(submission):
    """Put the submission in a paid submission set and return its payment."""
    group = SubmissionSet.objects.create(
        user=submission.user,
        author=submission.author,
        contest=submission.theme.contest,
    )
    group.submissions.add(submission)
    return Payment.objects.create(submission_set=group, paid=True)


def first_link(message):
    """Return the first HTTPS link in a plain-text email body."""
    return next(
        line for line in message.body.splitlines() if line.startswith("https://")
    )


def registration(email, address):
    """Return a valid registration request for a new account."""
    return {
        "email": email,
        "password": "Original!73",
        "first_name": "New",
        "last_name": "Account",
        **address,
    }


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
                pytest.fail("The other connection never waited for this one.")
            time.sleep(0.01)
