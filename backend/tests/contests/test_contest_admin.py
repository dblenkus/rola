"""Set up a contest in the Django admin."""

import pytest
from django.test import Client
from django.utils import timezone

pytestmark = pytest.mark.django_db


def split_datetime(prefix, value):
    """Return the admin's date and time inputs for a datetime field."""
    local = timezone.localtime(value)
    return {
        f"{prefix}_0": local.strftime("%Y-%m-%d"),
        f"{prefix}_1": local.strftime("%H:%M:%S"),
    }


def test_contest_change_form_sets_the_club_and_school_visibility(world):
    contest = world.contest
    browser = Client()
    browser.force_login(world.admin)
    url = f"/django-admin/contests/contest/{contest.pk}/change/"

    form = browser.get(url).context["adminform"].form
    assert {"club_visible", "school_visible"} <= set(form.fields)

    data = {
        "title": contest.title,
        "description": "",
        **split_datetime("start_date", contest.start_date),
        **split_datetime("end_date", contest.end_date),
        **split_datetime("publish_date", contest.publish_date),
        "club_visible": "on",
        "club_required": "on",
        "school_visible": "on",
        "notice_html": "<p>Notice</p>",
        "confirmation_html": "<p>Thanks</p>",
        "confirmation_email": "",
        "themes-TOTAL_FORMS": "1",
        "themes-INITIAL_FORMS": "1",
        "themes-MIN_NUM_FORMS": "0",
        "themes-MAX_NUM_FORMS": "1000",
        "themes-0-id": str(world.theme.pk),
        "themes-0-contest": str(contest.pk),
        "themes-0-title": world.theme.title,
        "themes-0-max_photos": str(world.theme.max_photos),
    }
    response = browser.post(url, data)

    assert response.status_code == 302
    contest.refresh_from_db()
    assert contest.club_visible is True
    assert contest.club_required is True
    assert contest.school_visible is True
    assert contest.school_required is False
