"""Parsers for image uploads."""

from rest_framework import parsers


class ImageUploadParser(parsers.FileUploadParser):
    """Parse raw image upload requests."""

    media_type = "image/jpeg"
