"""Download a contest's photographs."""

import shutil
import tempfile
import time
import zipfile

from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.utils.text import slugify

from rola.contests.models import Contest, Theme
from rola.entries.models import Submission


@login_required
def download_contest(request, contest_id):
    """Download all submissions of the contest as zip file.

    The archive is as large as the contest's photographs together, so it is
    built in a temporary file instead of in memory.
    """
    contest = get_object_or_404(Contest, pk=contest_id)
    if not (request.user.is_superuser or contest.user_id == request.user.pk):
        return HttpResponseForbidden("Only the organizer can download this contest.")

    # The response closes the file, which deletes it.
    archive = tempfile.TemporaryFile()  # noqa: SIM115
    try:
        write_contest_archive(contest, archive)
    except BaseException:
        archive.close()
        raise
    archive.seek(0)
    return FileResponse(
        archive,
        as_attachment=True,
        filename=f"{slugify(contest.title)}.zip",
        content_type="application/x-zip-compressed",
    )


def write_contest_archive(contest, archive):
    """Write every photograph of the contest's submissions into a zip archive.

    The ``exportcontest`` command writes the same archive to a file on the
    server, for a contest whose download takes too long.

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
