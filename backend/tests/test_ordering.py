"""Return published results in a stable order on every page and request."""

from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from rolca.core.models import Submission
from rolca.rating.models import Judge, Rating, ThemeResults

pytestmark = pytest.mark.django_db


@pytest.fixture
def scores(world):
    """Publish 60 accepted submissions sharing three scores, keyed by primary key."""
    judge = Judge.objects.create(judge=world.other, contest=world.contest)
    submissions = Submission.objects.bulk_create(
        Submission(
            user=world.owner,
            author=world.author,
            theme=world.theme,
            title=f"Photo {index}",
        )
        for index in range(60)
    )
    result = {
        submission.pk: 3 + index % 3 for index, submission in enumerate(submissions)
    }
    Rating.objects.bulk_create(
        Rating(user=world.other, judge=judge, submission_id=pk, rating=score)
        for pk, score in result.items()
    )
    ThemeResults.objects.create(theme=world.theme, accepted_threshold=3)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    return result


def test_result_pages_ordered_by_tied_scores_return_each_submission_once(scores):
    # PostgreSQL returns tied rows in a different order for each LIMIT and
    # OFFSET unless the ordering ends with a unique key.
    client = APIClient()
    rows = []
    page = 1
    while page:
        response = client.get(
            "/api/v1/results/submission",
            {"ordering": "-rating_sum", "page_size": 7, "page": page},
        )
        assert response.status_code == 200, response.data
        rows.extend((row["rating"], row["id"]) for row in response.data["results"])
        page = page + 1 if response.data["next"] else None

    assert rows == sorted(
        ((score, pk) for pk, score in scores.items()),
        key=lambda row: (-row[0], row[1]),
    )


def test_theme_results_list_submissions_by_primary_key(world, scores):
    response = APIClient().get(f"/api/v1/results/theme/{world.theme.pk}")

    assert response.status_code == 200, response.data
    assert [row["id"] for row in response.data["submissions"]] == sorted(scores)
