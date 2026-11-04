"""Exercise image processing and the historical thumbnail migration."""

import importlib

import pytest
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from PIL import Image

from drf_user.models import User
from rolca.core.models import File
from tests.test_workflows import PASSWORD, photo

pytestmark = pytest.mark.django_db


def test_upload_creates_jpeg_thumbnail():
    user = User.objects.create_user("photographer@example.org", PASSWORD)
    image = photo(user)
    with image.thumbnail.open("rb") as source, Image.open(source) as thumb:
        assert thumb.size == (400, 300)
        assert thumb.format == "JPEG"


def test_historical_thumbnail_migration_handles_existing_media():
    image = photo(User.objects.create_user("photographer@example.org", PASSWORD))
    state = MigrationLoader(connection).project_state(
        [("core", "0016_submissionset_update_3")]
    )
    migration = importlib.import_module("rolca.core.migrations.0017_enlarge_thumbnails")
    migration.enlarge_thumbnails(state.apps, None)
    image.refresh_from_db()
    with image.thumbnail.open("rb") as source, Image.open(source) as thumbnail:
        assert thumbnail.size == (400, 300)
        assert thumbnail.format == "JPEG"
    assert File.objects.count() == 1
