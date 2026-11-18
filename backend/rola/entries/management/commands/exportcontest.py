"""Write a contest's photographs into a zip archive on the server."""

import os

from django.core.management.base import BaseCommand, CommandError

from rola.contests.models import Contest
from rola.entries.views import write_contest_archive


class Command(BaseCommand):
    """Write the contest download's archive to a new file."""

    help = (
        "Write the zip archive that the contest download in the Django admin "
        "sends to a new file, without the download's time limit."
    )

    def add_arguments(self, parser):
        """Accept the contest's id and the archive's path."""
        parser.add_argument("contest_id", type=int, help="Id of the contest.")
        parser.add_argument(
            "path", help="Path of the archive to create; it must not exist yet."
        )

    def handle(self, *args, **options):
        """Write the archive, leaving no part of it behind if that fails."""
        contest_id, path = options["contest_id"], options["path"]
        try:
            contest = Contest.objects.get(pk=contest_id)
        except Contest.DoesNotExist:
            raise CommandError(f"Contest {contest_id} does not exist.") from None

        # Exclusive creation keeps an existing file, such as an earlier
        # archive, from being overwritten, and from being removed below.
        try:
            archive = open(path, "xb")  # noqa: SIM115
        except FileExistsError:
            raise CommandError(f"{path} already exists.") from None
        try:
            with archive:
                write_contest_archive(contest, archive)
        # BaseException also covers Ctrl-C, which a long export invites.
        except BaseException:
            os.remove(path)
            raise
