"""Build accounts, photographs and submissions for backend tests."""

import io

from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image

from rola.accounts.models import User
from rola.contests.models import File, Submission, SubmissionSet
from rola.payments.models import Payment

PASSWORD = "test-only-passphrase-A9!"


def create_user(name, *, superuser=False):
    """Create an active account with the address ``<name>@example.org``."""
    create = User.objects.create_superuser if superuser else User.objects.create_user
    return create(f"{name}@example.org", PASSWORD, is_active=True)


def photo(user, name="photo.jpg"):
    """Create a stored JPEG belonging to the given account."""
    data = io.BytesIO()
    Image.new("RGB", (800, 600), "red").save(data, "JPEG")
    return File.objects.create(
        user=user,
        file=SimpleUploadedFile(name, data.getvalue(), content_type="image/jpeg"),
    )


def payload(world, **changes):
    """Build a submission request using a photograph owned by the submitter."""
    result = {
        "title": "Photo",
        "theme": world.theme.pk,
        "author": {"id": world.author.pk},
        "files": [{"id": photo(world.owner).pk}],
    }
    result.update(changes)
    return result


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
    return Payment.objects.create(submissionset=group, paid=True)
