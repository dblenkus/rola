"""Exercise image processing of uploaded photographs."""

import pytest
from PIL import Image

from drf_user.models import User
from tests.test_workflows import PASSWORD, photo

pytestmark = pytest.mark.django_db


def test_upload_creates_jpeg_thumbnail():
    user = User.objects.create_user("photographer@example.org", PASSWORD)
    image = photo(user)
    with image.thumbnail.open("rb") as source, Image.open(source) as thumb:
        assert thumb.size == (400, 300)
        assert thumb.format == "JPEG"
