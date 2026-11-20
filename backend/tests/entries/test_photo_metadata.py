"""Strip identifying metadata from photographs and refuse uploads that are not JPEG."""

import io
import os
import struct

import pytest
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.management import call_command
from PIL import ExifTags, Image, ImageCms

from rola.entries.models import File

pytestmark = pytest.mark.django_db


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
        "/api/v1/files",
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
