"""Filter the contest and institution lists."""

from datetime import timedelta

import pytest
from django.utils import timezone

from rola.contests.models import Contest, Institution, Theme
from tests.factories import (
    submitted,
)

pytestmark = pytest.mark.django_db


def test_contest_and_institution_filters_are_applied(world):
    Contest.objects.create(
        title="Past",
        start_date=timezone.now() - timedelta(days=4),
        end_date=timezone.now() - timedelta(days=2),
    )
    response = world.client.get("/api/v1/contest", {"is_active": "true"})
    assert [item["id"] for item in response.data["results"]] == [world.contest.pk]
    desired = Institution.objects.create(kind=1, name="School")
    Institution.objects.create(kind=1, name="Elsewhere")
    response = world.client.get("/api/v1/institution", {"name": "School"})
    assert [item["id"] for item in response.data["results"]] == [desired.pk]


def test_submitted_contest_filter_lists_each_contest_once(world):
    for _ in range(3):
        submitted(world)
    other = Contest.objects.create(
        title="Other",
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    other_theme = Theme.objects.create(contest=other, title="City", max_photos=4)
    submitted(world, user=world.other, author=world.other_author, theme=other_theme)
    response = world.client.get("/api/v1/contest", {"submitted": "true"})
    assert response.data["count"] == 1
    assert [item["id"] for item in response.data["results"]] == [world.contest.pk]
    response = world.client.get("/api/v1/contest", {"submitted": "false"})
    assert response.data["count"] == 1
    assert [item["id"] for item in response.data["results"]] == [other.pk]
