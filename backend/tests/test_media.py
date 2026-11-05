"""Exercise image processing and storage of uploaded photographs."""

import logging
from datetime import timedelta

import pytest
from django.core.files.storage import FileSystemStorage, default_storage
from django.db import transaction
from django.utils import timezone
from PIL import Image

from drf_user.models import User
from rolca.core.models import Author, Contest, File, SubmissionSet
from tests.factories import create_user, photo, submitted

pytestmark = pytest.mark.django_db


def test_upload_creates_jpeg_thumbnail():
    image = photo(create_user("photographer"))
    with image.thumbnail.open("rb") as source, Image.open(source) as thumb:
        assert thumb.size == (400, 300)
        assert thumb.format == "JPEG"


def stored_names(image):
    """Return the storage names of a photograph and its thumbnail."""
    return [image.file.name, image.thumbnail.name]


def assert_stored(names, expected):
    """Check whether storage still holds each of the given names."""
    assert [default_storage.exists(name) for name in names] == [expected] * len(names)


@pytest.mark.parametrize("endpoint", ["submission", "submissionset"])
def test_deleting_a_submission_removes_its_images_from_storage(
    world, endpoint, django_capture_on_commit_callbacks
):
    item = submitted(world)
    image = photo(world.owner)
    item.files.add(image)
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(item)
    names = stored_names(image)
    assert_stored(names, True)
    target = item if endpoint == "submission" else group
    with django_capture_on_commit_callbacks(execute=True):
        response = world.client.delete(f"/api/v1/{endpoint}/{target.pk}")
    assert response.status_code == 204
    assert not File.objects.exists()
    assert_stored(names, False)


def test_a_failed_photograph_delete_still_deletes_the_thumbnail(
    world, monkeypatch, caplog, django_capture_on_commit_callbacks
):
    item = submitted(world)
    image = photo(world.owner)
    item.files.add(image)
    photograph, thumbnail = stored_names(image)
    delete = FileSystemStorage.delete

    def delete_failing_for_photographs(storage, name):
        if name.startswith("photos/"):
            raise OSError("storage unavailable")
        delete(storage, name)

    monkeypatch.setattr(FileSystemStorage, "delete", delete_failing_for_photographs)
    with django_capture_on_commit_callbacks(execute=True):
        response = world.client.delete(f"/api/v1/submission/{item.pk}")
    assert response.status_code == 204
    assert_stored([photograph], True)
    assert_stored([thumbnail], False)
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(photograph in message for message in errors)
    assert not any(thumbnail in message for message in errors)


def test_images_stay_when_the_delete_is_rolled_back(
    world, django_capture_on_commit_callbacks
):
    item = submitted(world)
    image = photo(world.owner)
    item.files.add(image)
    with (
        django_capture_on_commit_callbacks(execute=True),
        pytest.raises(RuntimeError),
        transaction.atomic(),
    ):
        item.delete()
        raise RuntimeError("abort")
    assert File.objects.filter(pk=image.pk).exists()
    assert_stored(stored_names(image), True)


def test_images_another_file_references_stay_in_storage(
    world, django_capture_on_commit_callbacks
):
    item = submitted(world)
    image = photo(world.owner)
    item.files.add(image)
    (copy,) = File.objects.bulk_create(
        [File(user=world.owner, file=image.file.name, thumbnail=image.thumbnail.name)]
    )
    names = stored_names(image)
    with django_capture_on_commit_callbacks(execute=True):
        item.delete()
    assert_stored(names, True)
    with django_capture_on_commit_callbacks(execute=True):
        copy.delete()
    assert_stored(names, False)


def entered_photograph(world):
    """Enter one photograph in the fixture contest as a submission set."""
    item = submitted(world)
    image = photo(world.owner)
    item.files.add(image)
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(item)
    return image


@pytest.mark.parametrize(
    "schedule",
    [
        # Closed but not yet published: the jury may still be rating them.
        {"end_date": -timedelta(hours=1)},
        # Published before the end date, which closes entries as well.
        {"end_date": timedelta(days=1), "publish_date": -timedelta(hours=1)},
    ],
    ids=["ended", "published_before_end"],
)
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("delete", "author/{author.pk}"),
        ("patch", "author/{author.pk}"),
        ("delete", "user/{owner.id}"),
    ],
)
def test_closed_entries_survive_author_and_account_deletes(
    world, schedule, method, path, django_capture_on_commit_callbacks
):
    image = entered_photograph(world)
    now = timezone.now()
    Contest.objects.filter(pk=world.contest.pk).update(
        **{field: now + offset for field, offset in schedule.items()}
    )
    url = "/api/v1/" + path.format(author=world.author, owner=world.owner)
    data = {"first_name": "Renamed"} if method == "patch" else None
    with django_capture_on_commit_callbacks(execute=True):
        response = getattr(world.client, method)(url, data, format="json")
    assert response.status_code == 403
    assert response.data["detail"] == (
        "Entries in a closed contest can no longer be changed."
    )
    assert User.objects.filter(pk=world.owner.pk).exists()
    assert Author.objects.get(pk=world.author.pk).first_name == "Alice"
    assert SubmissionSet.objects.filter(submissions__files=image).exists()
    assert_stored(stored_names(image), True)


def test_deleting_an_author_of_open_entries_deletes_its_photographs(
    world, django_capture_on_commit_callbacks
):
    names = stored_names(entered_photograph(world))
    with django_capture_on_commit_callbacks(execute=True):
        response = world.client.delete(f"/api/v1/author/{world.author.pk}")
    assert response.status_code == 204
    assert not Author.objects.filter(pk=world.author.pk).exists()
    assert not File.objects.exists()
    assert_stored(names, False)


def test_deleting_an_account_of_open_entries_deletes_its_photographs(
    world, django_capture_on_commit_callbacks
):
    names = stored_names(entered_photograph(world))
    with django_capture_on_commit_callbacks(execute=True):
        response = world.client.delete(f"/api/v1/user/{world.owner.id}")
    assert response.status_code == 204
    assert not User.objects.filter(pk=world.owner.pk).exists()
    assert not File.objects.exists()
    assert_stored(names, False)
