"""Answer API requests only in JSON."""

import pytest

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
