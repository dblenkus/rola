"""Check, strip, thumbnail and name the uploaded photographs.

:func:`strip_metadata` removes identifying metadata from a JPEG photograph
without decoding it.
"""

import hashlib
import io
import os
import struct
import time

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile
from PIL import Image, ImageOps

#: EXIF tag that says how to rotate the image for display.
ORIENTATION = 0x0112

_SOI = b"\xff\xd8"
_EOI = 0xD9
_SOS = 0xDA
_APP0 = 0xE0
_APP1 = 0xE1
_APP2 = 0xE2
_APP14 = 0xEE
_APP15 = 0xEF
_COM = 0xFE

#: Identifier, version, density units and densities of a JFIF header, which
#: the thumbnail's width and height and pixels follow.
_JFIF = b"JFIF\x00"
_JFIF_HEADER_LENGTH = 12
_EXIF = b"Exif\x00\x00"
_ICC_PROFILE = b"ICC_PROFILE\x00"
_ADOBE = b"Adobe"


def strip_metadata(data: bytes) -> bytes:
    """Remove the metadata that could identify a photograph's author or place.

    The segments that hold the compressed image are copied unchanged, so the
    result decodes to the same pixels. Of the metadata, it keeps the JFIF
    header without its thumbnail, the ICC colour profile, the Adobe colour
    transform and, of the EXIF data, only the orientation. It drops every
    other EXIF tag (such as the camera owner, the copyright holder and the
    GPS position, and the embedded thumbnail), XMP, IPTC, multi-picture and
    other application data, comments, and anything after the end of the
    image, such as further pictures.

    :param data: A complete JPEG file.
    :return: The JPEG file without that metadata.
    :raises ValueError: If ``data`` is not a well-formed JPEG file.
    """
    if not data.startswith(_SOI):
        raise ValueError("The data does not start with a JPEG start-of-image marker.")
    output = [_SOI]
    position = len(_SOI)
    while True:
        marker, position = _read_marker(data, position)
        if marker == _EOI:
            output.append(bytes([0xFF, _EOI]))
            return b"".join(output)
        # Restart, start-of-image and reserved markers cannot start a segment.
        if marker < 0xC0 or 0xD0 <= marker <= 0xD8:
            raise ValueError(f"Unexpected JPEG marker 0x{marker:02X}.")
        if position + 2 > len(data):
            raise ValueError("The JPEG data ends inside a segment.")
        (length,) = struct.unpack_from(">H", data, position)
        end = position + length
        if length < 2 or end > len(data):
            raise ValueError("A JPEG segment runs past the end of the data.")
        payload = _kept_payload(marker, data[position + 2 : end])
        if payload is not None:
            output.append(bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2))
            output.append(payload)
        position = end
        if marker == _SOS:
            scan_end = _scan_end(data, position)
            output.append(data[position:scan_end])
            position = scan_end


def _read_marker(data: bytes, position: int) -> tuple[int, int]:
    """Return the marker at a position and the position after it.

    Any number of 0xFF fill bytes may precede a marker.
    """
    if position >= len(data):
        raise ValueError("The JPEG data ends before its end-of-image marker.")
    if data[position] != 0xFF:
        raise ValueError(f"Expected a JPEG marker at byte {position}.")
    while position < len(data) and data[position] == 0xFF:
        position += 1
    if position == len(data):
        raise ValueError("The JPEG data ends before its end-of-image marker.")
    return data[position], position + 1


def _scan_end(data: bytes, position: int) -> int:
    """Return where the entropy-coded data of a scan that starts at a position ends.

    The data ends at the first marker other than a restart marker; a 0xFF
    byte of the data itself is followed by a zero byte.
    """
    while True:
        start = data.find(b"\xff", position)
        if start == -1:
            raise ValueError("The JPEG data ends inside a scan.")
        position = start
        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position == len(data):
            raise ValueError("The JPEG data ends inside a scan.")
        following = data[position]
        if following != 0x00 and not 0xD0 <= following <= 0xD7:
            return start
        position += 1


def _kept_payload(marker: int, payload: bytes) -> bytes | None:
    """Return the payload to write for a segment, or None to leave it out.

    Every segment other than an application segment or a comment describes
    how to decode the image, so it is kept unchanged.
    """
    if marker == _APP0:
        if not payload.startswith(_JFIF):
            return None
        if len(payload) < _JFIF_HEADER_LENGTH + 2:
            raise ValueError("The JFIF header is too short.")
        # Declare a thumbnail of zero by zero pixels and leave its pixels out.
        return payload[:_JFIF_HEADER_LENGTH] + b"\x00\x00"
    if marker == _APP1:
        if not payload.startswith(_EXIF):
            return None
        orientation = _orientation(payload[len(_EXIF) :])
        return None if orientation is None else _orientation_exif(orientation)
    if marker == _APP2:
        return payload if payload.startswith(_ICC_PROFILE) else None
    if marker == _APP14:
        return payload if payload.startswith(_ADOBE) else None
    if _APP0 <= marker <= _APP15 or marker == _COM:
        return None
    return payload


def _orientation(tiff: bytes) -> int | None:
    """Return the orientation in the first image directory of EXIF data.

    :param tiff: The TIFF structure that follows the EXIF identifier.
    :return: The orientation, 1 to 8, or None if the data has no valid one.
    """
    byte_order = {b"II": "<", b"MM": ">"}.get(tiff[:2])
    if byte_order is None or len(tiff) < 8:
        return None
    magic, directory = struct.unpack_from(byte_order + "HI", tiff, 2)
    if magic != 42 or directory + 2 > len(tiff):
        return None
    (count,) = struct.unpack_from(byte_order + "H", tiff, directory)
    for index in range(count):
        entry = directory + 2 + 12 * index
        if entry + 12 > len(tiff):
            return None
        tag, kind, values = struct.unpack_from(byte_order + "HHI", tiff, entry)
        if tag == ORIENTATION:
            # One SHORT value, stored in the entry itself.
            if kind != 3 or values != 1:
                return None
            (orientation,) = struct.unpack_from(byte_order + "H", tiff, entry + 8)
            return orientation if 1 <= orientation <= 8 else None
    return None


def _orientation_exif(orientation: int) -> bytes:
    """Return an EXIF payload that holds only the given orientation.

    It is a big-endian TIFF header followed by one image directory with a
    single SHORT entry and no next directory.
    """
    return (
        _EXIF
        + b"MM\x00\x2a"
        + struct.pack(">IHHHIHHI", 8, 1, ORIENTATION, 3, 1, orientation, 0, 0)
    )


def validate_image(file):
    """Validate the upload size, format and longest image edge.

    The photograph must be a JPEG file whose metadata can be stripped.
    """
    max_size = settings.ENTRIES_MAX_UPLOAD_SIZE
    if file.size > max_size:
        raise ValidationError(f"Max size of file is {max_size}B.")

    # Pillow reports a JPEG file that holds further pictures, as many
    # cameras write it, as MPO; stripping keeps only its first picture.
    if file.image.format not in ("JPEG", "MPO"):
        raise ValidationError("Photographs must be JPEG files.")

    max_res = settings.ENTRIES_MAX_UPLOAD_RESOLUTION
    if max(file.image.size) > max_res:
        raise ValidationError(f"Max photo resolution is {max_res}px.")

    file.seek(0)
    try:
        strip_metadata(file.read())
    except ValueError as error:
        raise ValidationError("The photograph is not a valid JPEG file.") from error
    finally:
        file.seek(0)


def create_thumbnail(photograph):
    """Return a JPEG thumbnail of the photograph, at most 400 pixels on each edge.

    :param photograph: The stored photograph's file, without its metadata.
    :return: The thumbnail, named like the photograph.
    """
    thumb = io.BytesIO()
    with Image.open(photograph) as image:
        # The thumbnail carries no EXIF data, so its pixels take the
        # orientation that viewers apply to the stored photograph.
        ImageOps.exif_transpose(image, in_place=True)
        image.thumbnail((400, 400), Image.Resampling.LANCZOS)
        image.save(thumb, format="jpeg", quality=80, optimize=True, progressive=True)
    return InMemoryUploadedFile(
        thumb, None, photograph.name, "image/jpeg", thumb.tell(), None
    )


def _generate_filename(instance, filename, prefix):
    """Generate unique filename with given prefix."""
    md5 = hashlib.md5()
    md5.update(struct.pack("f", time.time()))
    was_closed = instance.file.closed
    try:
        if was_closed:
            instance.file.open("rb")
        for chunk in instance.file.chunks():
            md5.update(chunk)
    finally:
        if was_closed:
            instance.file.close()
    extension = os.path.splitext(filename)[1]
    return os.path.join(prefix, md5.hexdigest() + extension)


def generate_file_filename(instance, filename):
    """Generate filename for uploaded photo."""
    return _generate_filename(instance, filename, "photos")


def generate_thumb_filename(instance, filename):
    """Generate filename for thumbnails of uploaded photos."""
    return _generate_filename(instance, filename, "thumbs")
