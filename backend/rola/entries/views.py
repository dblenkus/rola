"""Download a contest's photographs."""

import tempfile

from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.utils.text import slugify

from rola.contests.models import Contest
from rola.entries.archive import write_contest_archive


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
