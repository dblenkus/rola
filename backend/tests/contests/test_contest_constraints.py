"""Keep a required club or school visible on the author form."""

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone

from rola.contests.models import Contest

pytestmark = pytest.mark.django_db

MESSAGES = {
    "club": 'A required club must be visible: tick "Club visible" or untick '
    '"Club required".',
    "school": 'A required school must be visible: tick "School visible" or '
    'untick "School required".',
}


def contest_with(field, *, visible, required):
    """Return an unsaved contest with the given visibility and requirement."""
    now = timezone.now()
    return Contest(
        title="Salon",
        start_date=now - timedelta(days=1),
        end_date=now + timedelta(days=1),
        publish_date=now + timedelta(days=2),
        notice_html="<p>Notice</p>",
        confirmation_html="<p>Thanks</p>",
        **{f"{field}_visible": visible, f"{field}_required": required},
    )


@pytest.mark.parametrize("field", ["club", "school"])
def test_the_database_refuses_a_required_field_that_is_hidden(field):
    with pytest.raises(IntegrityError), transaction.atomic():
        contest_with(field, visible=False, required=True).save()
    assert not Contest.objects.exists()


@pytest.mark.parametrize("field", ["club", "school"])
@pytest.mark.parametrize(
    ("visible", "required"), [(True, True), (True, False), (False, False)]
)
def test_the_database_accepts_a_visible_or_optional_field(field, visible, required):
    contest_with(field, visible=visible, required=required).save()

    stored = Contest.objects.values(f"{field}_visible", f"{field}_required").get()
    assert stored == {f"{field}_visible": visible, f"{field}_required": required}


@pytest.mark.parametrize("field", ["club", "school"])
def test_validation_refuses_a_required_field_that_is_hidden(field):
    with pytest.raises(ValidationError) as error:
        contest_with(field, visible=False, required=True).full_clean()
    assert error.value.messages == [MESSAGES[field]]
