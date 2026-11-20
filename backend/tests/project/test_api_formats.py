"""Accept and answer API requests only in JSON."""

import io

import pytest
from drf_spectacular.generators import SchemaGenerator
from PIL import Image

from rola.entries.models import Author
from tests.factories import (
    submitted,
)

pytestmark = pytest.mark.django_db


def test_the_api_answers_only_json(world):
    submitted(world, title="Unpublished entry")
    world.client.force_authenticate(world.other)
    browsable = world.client.get("/api/v1/rating?format=api")
    assert browsable.status_code == 404
    html = world.client.get("/api/v1/rating", HTTP_ACCEPT="text/html")
    assert html.status_code == 406
    for response in [browsable, html]:
        assert response["Content-Type"] == "application/json"
        assert b"Unpublished entry" not in response.content


def test_request_bodies_are_json_only(world):
    form = world.client.post(
        "/api/v1/authors",
        "first_name=Form&last_name=Encoded",
        content_type="application/x-www-form-urlencoded",
    )
    multipart = world.client.post(
        "/api/v1/authors",
        {"first_name": "Multi", "last_name": "Part"},
        format="multipart",
    )
    for response in [form, multipart]:
        assert response.status_code == 415, response.data
    assert not Author.objects.filter(first_name__in=["Form", "Multi"]).exists()

    jpeg = io.BytesIO()
    Image.new("RGB", (100, 100)).save(jpeg, "JPEG")
    upload = world.client.post(
        "/api/v1/files",
        jpeg.getvalue(),
        content_type="image/jpeg",
        headers={"Content-Disposition": 'attachment; filename="photo.jpg"'},
    )
    assert upload.status_code == 201, upload.data


def test_schema_declares_only_json_and_jpeg_bodies():
    schema = SchemaGenerator().get_schema(request=None, public=True)
    media_types = {
        media_type
        for operations in schema["paths"].values()
        for operation in operations.values()
        for media_type in operation.get("requestBody", {}).get("content", {})
    }
    assert media_types == {"application/json", "image/jpeg"}
