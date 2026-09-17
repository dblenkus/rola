import unittest
from datetime import timedelta

from django.utils import timezone

from rolca.core.models import Author, Contest, Submission, Theme


class DatabaseTestCase(unittest.TestCase):
    def test_contest_str(self):
        contest = Contest(title="Test contest")
        self.assertEqual(str(contest), "Test contest")

    def test_contest_active(self):
        contest = Contest()
        now = timezone.now()
        day = timedelta(days=1)

        # active contest
        contest.start_date = now - day
        contest.end_date = now + day
        self.assertTrue(contest.is_active())

        # past contest
        contest.start_date = now - 2 * day
        contest.end_date = now - day
        self.assertFalse(contest.is_active())

        # future contest
        contest.start_date = now + day
        contest.end_date = now + 2 * day
        self.assertFalse(contest.is_active())

    def test_theme_str(self):
        theme = Theme(title="Test theme")
        self.assertEqual(str(theme), "Test theme")

    def test_participant_str(self):
        participent = Author(first_name="Janez", last_name="Novak")
        self.assertEqual(str(participent), "Janez Novak")

    def test_submission_str(self):
        submission = Submission(title="Test submission")
        self.assertEqual(str(submission), "Test submission")
