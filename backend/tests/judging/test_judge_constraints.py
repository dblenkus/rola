"""Keep an account a judge of a contest at most once."""

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone

from rola.contests.models import Contest
from rola.judging.models import Judge
from tests.factories import create_user


def create_contest(title="Salon"):
    """Create a contest in judging."""
    now = timezone.now()
    return Contest.objects.create(
        title=title,
        start_date=now - timedelta(days=2),
        end_date=now - timedelta(days=1),
        publish_date=now + timedelta(days=1),
    )


@pytest.mark.django_db
def test_an_account_judges_a_contest_once():
    contest = create_contest()
    account = create_user("judge")
    judge = Judge.objects.create(contest=contest, judge=account)

    with pytest.raises(IntegrityError), transaction.atomic():
        Judge.objects.create(contest=contest, judge=account)
    assert list(Judge.objects.values_list("pk", flat=True)) == [judge.pk]


@pytest.mark.django_db
def test_an_account_judges_several_contests_and_a_contest_has_several_judges():
    contest, other_contest = create_contest(), create_contest("Other salon")
    account, other_account = create_user("judge"), create_user("other")

    Judge.objects.create(contest=contest, judge=account)
    Judge.objects.create(contest=other_contest, judge=account)
    Judge.objects.create(contest=contest, judge=other_account)

    assert Judge.objects.count() == 3


@pytest.mark.django_db
def test_validation_refuses_a_second_judge_row_for_one_account():
    contest = create_contest()
    account = create_user("judge")
    Judge.objects.create(contest=contest, judge=account)

    with pytest.raises(ValidationError) as error:
        Judge(contest=contest, judge=account).full_clean()
    assert error.value.messages == ["This account is already a judge of this contest."]
