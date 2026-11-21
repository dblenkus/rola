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


def change_url(contest):
    """Return the admin's change form URL of the contest."""
    return f"/django-admin/contests/contest/{contest.pk}/change/"


def admin_browser(world):
    """Return a browser logged in to the admin as the world's superuser."""
    browser = Client()
    browser.force_login(world.admin)
    return browser


def change_form_data(world, **flags):
    """Return the contest change form's data with the given ticked flags."""
    contest = world.contest
    return {
        "title": contest.title,
        "description": "",
        **split_datetime("start_date", contest.start_date),
        **split_datetime("end_date", contest.end_date),
        **split_datetime("publish_date", contest.publish_date),
        **{flag: "on" for flag, ticked in flags.items() if ticked},
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


def test_contest_change_form_sets_the_club_and_school_visibility(world):
    contest = world.contest
    browser = admin_browser(world)
    url = change_url(contest)

    form = browser.get(url).context["adminform"].form
    assert {"club_visible", "school_visible"} <= set(form.fields)

    data = change_form_data(
        world, club_visible=True, club_required=True, school_visible=True
    )
    response = browser.post(url, data)

    assert response.status_code == 302
    contest.refresh_from_db()
    assert contest.club_visible is True
    assert contest.club_required is True
    assert contest.school_visible is True
    assert contest.school_required is False


@pytest.mark.parametrize(
    ("field", "message"),
    [
        (
            "club",
            'A required club must be visible: tick "Club visible" or untick '
            '"Club required".',
        ),
        (
            "school",
            'A required school must be visible: tick "School visible" or '
            'untick "School required".',
        ),
    ],
)
def test_contest_change_form_refuses_a_required_field_that_is_hidden(
    world, field, message
):
    contest = world.contest
    browser = admin_browser(world)
    before = contest.modified

    response = browser.post(
        change_url(contest), change_form_data(world, **{f"{field}_required": True})
    )

    assert response.status_code == 200
    assert response.context["adminform"].form.non_field_errors() == [message]
    assert message in response.content.decode().replace("&quot;", '"')
    contest.refresh_from_db()
    assert contest.modified == before
    assert getattr(contest, f"{field}_required") is False


@pytest.mark.parametrize("field", ["club", "school"])
@pytest.mark.parametrize(
    ("visible", "required"), [(True, True), (True, False), (False, False)]
)
def test_contest_change_form_saves_a_visible_or_optional_field(
    world, field, visible, required
):
    contest = world.contest
    flags = {f"{field}_visible": visible, f"{field}_required": required}

    response = admin_browser(world).post(
        change_url(contest), change_form_data(world, **flags)
    )

    assert response.status_code == 302
    contest.refresh_from_db()
    assert getattr(contest, f"{field}_visible") is visible
    assert getattr(contest, f"{field}_required") is required
