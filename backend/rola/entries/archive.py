"""Write a contest's photographs into a zip archive."""

import shutil
import time
import zipfile

from django.utils.text import slugify

from rola.contests.models import Theme
from rola.entries.models import Submission


def write_contest_archive(contest, archive):
    """Write every photograph of the contest's submissions into a zip archive.

    The contest download in the Django admin sends the archive, and the
    ``exportcontest`` command writes it to a file on the server, for a
    contest whose download takes too long.

    :param contest: The contest to archive.
    :param archive: A binary file open for writing.
    """
    with zipfile.ZipFile(archive, mode="w") as zip_archive:
        for theme in Theme.objects.filter(contest=contest):
            theme_path = "/".join(
                [slugify(contest.title), f"{theme.pk}-{slugify(theme.title)}"]
            )
            zip_info = zipfile.ZipInfo(theme_path + "/")
            zip_archive.writestr(zip_info, "")

            no_title_count = 0
            for submission in Submission.objects.filter(theme=theme):
                if not submission.title:
                    no_title_count += 1
                zip_file_name = "{}.jpg".format(
                    slugify(f"{submission.author}-{submission.title or no_title_count}")
                )
                for file in submission.files.all():
                    zip_path = "/".join(
                        [
                            theme_path,
                            f"{submission.pk}-{file.pk}-{zip_file_name}",
                        ]
                    )
                    # Without a date, ZipInfo dates the photograph 1980-01-01.
                    entry = zipfile.ZipInfo(zip_path, date_time=time.localtime()[:6])
                    with (
                        file.file.open("rb") as source,
                        zip_archive.open(entry, "w") as target,
                    ):
                        shutil.copyfileobj(source, target)
