""".. Ignore pydocstyle D400.

==========
Core views
==========

.. autofunction:: rolca.core.views.upload

"""

import io
import json
import logging
import os
import zipfile

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotAllowed,
)
from django.shortcuts import get_object_or_404
from django.utils.text import slugify
from django.views.decorators.csrf import csrf_exempt

from rolca.core.models import Contest, File, Submission, Theme

logger = logging.getLogger(__name__)


@login_required
def download_contest(request, contest_id):
    """Download all submissions of the contest as zip file."""
    contest = get_object_or_404(Contest, pk=contest_id)
    if not (request.user.is_superuser or contest.user_id == request.user.pk):
        return HttpResponseForbidden("Only the organizer can download this contest.")

    buffer = io.BytesIO()
    zip_archive = zipfile.ZipFile(buffer, mode="w")

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
                with file.file.open("rb") as source:
                    zip_archive.writestr(zip_path, source.read())

    zip_archive.close()

    response = HttpResponse(
        buffer.getvalue(), content_type="application/x-zip-compressed"
    )

    slugified_title = slugify(contest.title)
    response["Content-Disposition"] = f'attachment; filename="{slugified_title}.zip"'
    response["Content-Length"] = buffer.tell()

    return response


@csrf_exempt
def upload(request):
    """Handle uploaded photo and create new File object."""
    if request.method != "POST":
        logger.warning("Upload request other than POST.")
        return HttpResponseNotAllowed(["POST"], "Only POST accepted")

    if not request.user.is_authenticated:
        logger.warning("Anonymous user tried to upload file.")
        return HttpResponseForbidden("Please login!")

    if request.FILES is None:
        logger.warning("Upload request without attached image.")
        return HttpResponseBadRequest("Must have files attached!")

    fn = request.FILES["files[]"]
    logger.info("Image received.")

    file_ = File(file=fn, user=request.user)

    if file_.file.size > settings.MAX_UPLOAD_SIZE:
        logger.warning("Too big file.")
        return HttpResponseBadRequest(
            f"File can't excede size of {settings.MAX_UPLOAD_SIZE / 1024}KB"
        )

    max_image_resolution = settings.MAX_IMAGE_RESOLUTION
    if max(file_.file.width, file_.file.height) > max_image_resolution:
        logger.warning("Too big file.")
        return HttpResponseBadRequest(
            f"File can't excede size of {settings.MAX_IMAGE_RESOLUTION}px"
        )

    file_.save()

    result = []
    result.append(
        {
            "name": os.path.basename(file_.file.name),
            "size": file_.file.size,
            "url": file_.file.url,
            "thumbnail": file_.thumbnail.url,
            "delete_url": "",
            "delete_type": "POST",
        }
    )
    response_data = json.dumps(result)
    return HttpResponse(response_data, content_type="application/json")
