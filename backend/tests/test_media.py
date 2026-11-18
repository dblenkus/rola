"""Exercise image processing and storage of uploaded photographs."""

import io
import logging
import os
import queue
import struct
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage, default_storage
from django.core.management import call_command
from django.db import connection, transaction
from django.utils import timezone
from PIL import ExifTags, Image, ImageCms

from rola.accounts.models import User
from rola.accounts.tests.test_account_security import (
    wait_until_blocked_by_this_connection,
)
from rola.contests.models import Author, Contest, File, SubmissionSet
from tests.factories import create_user, payload, photo, submitted

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


def test_replacing_a_photograph_deletes_the_old_one(
    world, django_capture_on_commit_callbacks
):
    item = submitted(world)
    kept, replaced = photo(world.owner), photo(world.owner)
    item.files.add(kept, replaced)
    new = photo(world.owner)
    with django_capture_on_commit_callbacks(execute=True):
        response = world.client.patch(
            f"/api/v1/submission/{item.pk}",
            {"files": [{"id": kept.pk}, {"id": new.pk}]},
            format="json",
        )
    assert response.status_code == 200, response.data
    assert set(item.files.values_list("pk", flat=True)) == {kept.pk, new.pk}
    assert not File.objects.filter(pk=replaced.pk).exists()
    assert_stored(stored_names(replaced), False)
    assert_stored(stored_names(kept) + stored_names(new), True)


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


def backdate(name, age):
    """Set the modification time of a stored file to ``age`` ago."""
    moment = (timezone.now() - age).timestamp()
    os.utime(default_storage.path(name), (moment, moment))


def clean_up(*args):
    """Run the orphan cleanup and return the lines it printed."""
    output = io.StringIO()
    call_command("deleteorphanphotos", *args, stdout=output)
    return output.getvalue().splitlines()


def test_cleanup_deletes_unattached_uploads_after_a_day(
    world, django_capture_on_commit_callbacks
):
    abandoned, recent, entered = (photo(world.owner) for _ in range(3))
    submitted(world).files.add(entered)
    File.objects.filter(pk__in=[abandoned.pk, entered.pk]).update(
        created=timezone.now() - timedelta(hours=25)
    )
    assert clean_up("--dry-run") == [
        "Unattached uploads to delete: 1",
        "Unreferenced images to delete: 0",
    ]
    assert File.objects.count() == 3
    # The stored images are recent, so only the receiver of the row delete
    # removes the abandoned upload's images.
    with django_capture_on_commit_callbacks(execute=True):
        assert clean_up() == [
            "Unattached uploads deleted: 1",
            "Unreferenced images deleted: 0",
        ]
    assert set(File.objects.values_list("pk", flat=True)) == {recent.pk, entered.pk}
    assert_stored(stored_names(abandoned), False)
    assert_stored(stored_names(recent) + stored_names(entered), True)


def test_cleanup_deletes_stored_photographs_no_file_references(world):
    day = timedelta(hours=25)
    orphans = [
        default_storage.save(name, ContentFile(b"orphan"))
        for name in ("photos/orphan.jpg", "thumbs/orphan.jpg")
    ]
    recent = default_storage.save("photos/recent.jpg", ContentFile(b"in progress"))
    header = default_storage.save("header.jpg", ContentFile(b"header"))
    world.contest.header_image = header
    world.contest.save()
    entered = photo(world.owner)
    submitted(world).files.add(entered)
    for name in [*orphans, header, *stored_names(entered)]:
        backdate(name, day)
    backdate(recent, timedelta(hours=23))
    assert clean_up("--dry-run") == [
        "Unattached uploads to delete: 0",
        "Unreferenced images to delete: 2",
    ]
    assert_stored(orphans, True)
    assert clean_up() == [
        "Unattached uploads deleted: 0",
        "Unreferenced images deleted: 2",
    ]
    assert_stored(orphans, False)
    assert_stored([recent, header, *stored_names(entered)], True)


def missing_object(name):
    """Return the error S3 raises for the metadata of a missing object."""
    return ClientError(
        {
            "Error": {"Code": "404", "Message": "Not Found"},
            "ResponseMetadata": {"HTTPStatusCode": 404},
        },
        "HeadObject",
    )


@pytest.mark.parametrize(
    "missing",
    [FileNotFoundError, missing_object],
    ids=["file_system", "s3"],
)
def test_cleanup_skips_an_image_deleted_after_the_listing(world, monkeypatch, missing):
    day = timedelta(hours=25)
    orphans = [
        default_storage.save(name, ContentFile(b"orphan"))
        for name in ("photos/orphan.jpg", "photos/vanished.jpg", "thumbs/orphan.jpg")
    ]
    for name in orphans:
        backdate(name, day)
    vanished = orphans.pop(1)
    get_modified_time = FileSystemStorage.get_modified_time

    def get_modified_time_of_a_deleted_image(storage, name):
        if name == vanished:
            # The image of an upload deleted after the cleanup listed it.
            storage.delete(name)
            raise missing(name)
        return get_modified_time(storage, name)

    monkeypatch.setattr(
        FileSystemStorage, "get_modified_time", get_modified_time_of_a_deleted_image
    )
    assert clean_up() == [
        "Unattached uploads deleted: 0",
        "Unreferenced images deleted: 2",
    ]
    assert_stored([*orphans, vanished], False)


def test_cleanup_stops_on_other_storage_errors(world, monkeypatch):
    orphan = default_storage.save("photos/orphan.jpg", ContentFile(b"orphan"))
    backdate(orphan, timedelta(hours=25))
    denied = ClientError(
        {
            "Error": {"Code": "403", "Message": "Forbidden"},
            "ResponseMetadata": {"HTTPStatusCode": 403},
        },
        "HeadObject",
    )

    def get_modified_time_denied(storage, name):
        raise denied

    monkeypatch.setattr(
        FileSystemStorage, "get_modified_time", get_modified_time_denied
    )
    with pytest.raises(ClientError) as raised:
        clean_up()
    assert raised.value is denied
    assert_stored([orphan], True)


@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="Row locks need PostgreSQL."
)
@pytest.mark.django_db(transaction=True)
def test_cleanup_keeps_an_old_upload_that_a_submission_is_attaching(world):
    image = photo(world.owner)
    File.objects.filter(pk=image.pk).update(
        created=timezone.now() - timedelta(hours=25)
    )
    backend_pids = queue.SimpleQueue()

    def clean_up_on_another_connection():
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pids.put(cursor.fetchone()[0])
            return clean_up()
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            response = world.client.post(
                "/api/v1/submission",
                payload(world, files=[{"id": image.pk}]),
                format="json",
            )
            cleanup = executor.submit(clean_up_on_another_connection)
            # The cleanup waits for the submission's lock on the upload and
            # then finds it attached.
            wait_until_blocked_by_this_connection(backend_pids.get(timeout=10))
        lines = cleanup.result(timeout=10)

    assert response.status_code == 201, response.data
    assert lines == [
        "Unattached uploads deleted: 0",
        "Unreferenced images deleted: 0",
    ]
    assert File.objects.get(pk=image.pk).submission_id == response.data["id"]


#: A JFIF header without a thumbnail, as the JPEG encoder writes it.
PLAIN_JFIF = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"

COLOUR_PROFILE = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()

#: Identifying text that the photograph's metadata carries.
IDENTIFYING = [
    b"Ana Novak",
    b"Novak Studio",
    b"xmp-creator",
    b"camera comment",
    b"iptc-byline",
    b"after the image",
]


def patterned_image(size=(64, 48)):
    """Return an RGB image whose pixels are not all alike."""
    width, height = size
    return Image.frombytes("RGB", size, bytes(range(256)) * (width * height * 3 // 256))


def photograph_with_metadata():
    """Return a JPEG with identifying metadata, an orientation and a colour profile."""
    exif = Image.Exif()
    exif[ExifTags.Base.Orientation] = 6
    exif[ExifTags.Base.Artist] = "Ana Novak"
    exif[ExifTags.Base.Copyright] = "Novak Studio"
    exif[ExifTags.IFD.GPSInfo] = {
        ExifTags.GPS.GPSLatitudeRef: "N",
        ExifTags.GPS.GPSLatitude: (46.0, 3.0, 12.0),
        ExifTags.GPS.GPSLongitudeRef: "E",
        ExifTags.GPS.GPSLongitude: (14.0, 30.0, 6.0),
    }
    byline = b"\x1c\x02\x50" + struct.pack(">H", 11) + b"iptc-byline"
    iptc = b"Photoshop 3.0\x00" + b"8BIM\x04\x04\x00\x00"
    iptc += struct.pack(">I", len(byline)) + byline + b"\x00"
    data = io.BytesIO()
    patterned_image().save(
        data,
        "JPEG",
        exif=exif,
        icc_profile=COLOUR_PROFILE,
        xmp=b"<x:xmpmeta><dc:creator>xmp-creator</dc:creator></x:xmpmeta>",
        comment=b"camera comment",
        extra=b"\xff\xed" + struct.pack(">H", len(iptc) + 2) + iptc,
    )
    jpeg = data.getvalue()
    with Image.open(io.BytesIO(jpeg)) as image:
        assert image.getexif().get_ifd(ExifTags.IFD.GPSInfo)
    assert jpeg[2:20] == PLAIN_JFIF
    # A JFIF header with a one-pixel thumbnail.
    jfif = b"\xff\xe0\x00\x13JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x01\x01\xab\xcd\xef"
    return jpeg[:2] + jfif + jpeg[20:] + b"after the image"


def upload(world, data):
    """Upload a photograph as the frontend does."""
    return world.client.post(
        "/api/v1/file",
        data,
        content_type="image/jpeg",
        headers={"Content-Disposition": 'attachment; filename="photo.jpg"'},
    )


def pixels(data):
    """Decode a stored or uploaded image."""
    with Image.open(io.BytesIO(data)) as image:
        return image.tobytes()


def assert_without_metadata(data):
    """Check that a JPEG keeps only its orientation and colour profile."""
    assert not [text for text in IDENTIFYING if text in data]
    assert data[2:20] == PLAIN_JFIF
    with Image.open(io.BytesIO(data)) as image:
        assert image.format == "JPEG"
        assert image.getexif() == {ExifTags.Base.Orientation: 6}
        assert image.info["icc_profile"] == COLOUR_PROFILE


def test_uploads_keep_only_orientation_and_colour_profile(world):
    original = photograph_with_metadata()
    response = upload(world, original)
    assert response.status_code == 201, response.data
    stored = File.objects.get(pk=response.data["id"])
    with stored.file.open("rb") as source:
        data = source.read()
    assert_without_metadata(data)
    assert pixels(data) == pixels(original)
    with stored.thumbnail.open("rb") as source, Image.open(source) as thumbnail:
        assert "comment" not in thumbnail.info
        assert not thumbnail.getexif()


def red_quarters(image):
    """Name the quarters of a red and white image whose centre is red."""
    width, height = image.size
    centres = {
        "top left": (width // 4, height // 4),
        "top right": (3 * width // 4, height // 4),
        "bottom left": (width // 4, 3 * height // 4),
        "bottom right": (3 * width // 4, 3 * height // 4),
    }
    # Red has no green, white has all of it.
    return {name for name, centre in centres.items() if image.getpixel(centre)[1] < 128}


@pytest.mark.parametrize(
    ("orientation", "size", "red"),
    [
        (3, (400, 300), "bottom right"),
        (6, (300, 400), "top right"),
        (8, (300, 400), "bottom left"),
    ],
)
def test_thumbnails_show_the_photograph_upright(world, orientation, size, red):
    # A camera stores its sensor's pixels with an EXIF orientation that turns
    # them upright for display, as viewers do with the stored photograph.
    sensor = Image.new("RGB", (1600, 1200), "white")
    sensor.paste("red", (0, 0, 800, 600))
    exif = Image.Exif()
    exif[ExifTags.Base.Orientation] = orientation
    data = io.BytesIO()
    sensor.save(data, "JPEG", exif=exif)

    response = upload(world, data.getvalue())

    assert response.status_code == 201, response.data
    stored = File.objects.get(pk=response.data["id"])
    with stored.thumbnail.open("rb") as source, Image.open(source) as thumbnail:
        assert not thumbnail.getexif()
        assert thumbnail.size == size
        assert red_quarters(thumbnail) == {red}


def test_multi_picture_uploads_keep_only_the_first_picture(world):
    first, second = patterned_image(), Image.new("RGB", (32, 24), "blue")
    data = io.BytesIO()
    first.save(data, "MPO", save_all=True, append_images=[second])
    original = data.getvalue()
    with Image.open(io.BytesIO(original)) as image:
        assert image.format == "MPO"
        first_picture = image.tobytes()
    response = upload(world, original)
    assert response.status_code == 201, response.data
    with File.objects.get(pk=response.data["id"]).file.open("rb") as source:
        stored = source.read()
    with Image.open(io.BytesIO(stored)) as image:
        assert image.format == "JPEG"
        assert image.tobytes() == first_picture
    assert len(stored) < len(original)


@pytest.mark.parametrize("image_format", ["PNG", "GIF", "TIFF"])
def test_non_jpeg_uploads_are_refused(world, image_format):
    data = io.BytesIO()
    patterned_image().save(data, image_format)
    response = upload(world, data.getvalue())
    assert response.status_code == 400
    assert response.data == {"file": ["Photographs must be JPEG files."]}
    assert not File.objects.exists()


def test_damaged_jpeg_uploads_are_refused(world):
    data = io.BytesIO()
    patterned_image().save(data, "JPEG")
    response = upload(world, data.getvalue()[:-100])
    assert response.status_code == 400
    assert response.data == {"file": ["The photograph is not a valid JPEG file."]}
    assert not File.objects.exists()


def strip(*args):
    """Run the metadata stripping command and return the lines it printed."""
    output = io.StringIO()
    call_command("stripphotometadata", *args, stdout=output)
    return output.getvalue().splitlines()


def stored_bytes(name):
    """Read a stored file."""
    with default_storage.open(name, "rb") as source:
        return source.read()


def test_strip_command_rewrites_existing_originals_in_place(world):
    original = photograph_with_metadata()
    plain, drawing, commented = io.BytesIO(), io.BytesIO(), io.BytesIO()
    patterned_image().save(plain, "JPEG")
    patterned_image().save(drawing, "PNG")
    # The thumbnails that the old deployment made carry the comment of the
    # photograph they were made from.
    patterned_image().save(
        commented, "JPEG", progressive=True, comment=b"camera comment"
    )
    tagged, untagged, png, thumbnail = (
        default_storage.save(name, ContentFile(data))
        for name, data in [
            ("photos/tagged.jpg", original),
            ("photos/untagged.jpg", plain.getvalue()),
            ("photos/drawing.png", drawing.getvalue()),
            ("thumbs/tagged.jpg", commented.getvalue()),
        ]
    )
    # Rows made without File.save, like those that the transfer copies.
    File.objects.bulk_create(
        [
            File(user=world.owner, file=tagged, thumbnail=thumbnail),
            *(File(user=world.owner, file=name) for name in [tagged, untagged, png]),
        ]
    )
    mode = os.stat(default_storage.path(tagged)).st_mode

    report = [
        "Not a valid JPEG file, left unchanged: photos/drawing.png",
        "Photographs and thumbnails rewritten: 2",
        "Photographs and thumbnails already without metadata: 1",
        "Files that are not valid JPEG photographs: 1",
        "Files that are not in storage: 0",
    ]
    assert strip() == report
    stripped = stored_bytes(tagged)
    assert_without_metadata(stripped)
    assert pixels(stripped) == pixels(original)
    assert os.stat(default_storage.path(tagged)).st_mode == mode
    stripped_thumbnail = stored_bytes(thumbnail)
    assert b"camera comment" not in stripped_thumbnail
    assert pixels(stripped_thumbnail) == pixels(commented.getvalue())
    assert stored_bytes(untagged) == plain.getvalue()
    assert stored_bytes(png) == drawing.getvalue()
    assert sorted(default_storage.listdir("photos")[1]) == [
        "drawing.png",
        "tagged.jpg",
        "untagged.jpg",
    ]
    assert default_storage.listdir("thumbs")[1] == ["tagged.jpg"]

    report[1:3] = [
        "Photographs and thumbnails rewritten: 0",
        "Photographs and thumbnails already without metadata: 3",
    ]
    assert strip() == report
    assert stored_bytes(tagged) == stripped
    assert stored_bytes(thumbnail) == stripped_thumbnail


def test_strip_command_reports_photographs_missing_from_storage(world):
    tagged = default_storage.save(
        "photos/tagged.jpg", ContentFile(photograph_with_metadata())
    )
    # A row that the transfer copied without its photograph, listed first.
    File.objects.bulk_create(
        File(user=world.owner, file=name) for name in ["photos/absent.jpg", tagged]
    )

    report = [
        "Not in storage, left unchanged: photos/absent.jpg",
        "Photographs and thumbnails rewritten: 1",
        "Photographs and thumbnails already without metadata: 0",
        "Files that are not valid JPEG photographs: 0",
        "Files that are not in storage: 1",
    ]
    assert strip() == report
    assert_without_metadata(stored_bytes(tagged))

    report[1:3] = [
        "Photographs and thumbnails rewritten: 0",
        "Photographs and thumbnails already without metadata: 1",
    ]
    assert strip() == report
