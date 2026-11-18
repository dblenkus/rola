"""Register the submitted entries in the Django admin."""

import tempfile

from django.contrib import admin
from django.http import FileResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.text import slugify

from rola.contests.admin import ContestAdmin
from rola.contests.models import Contest
from rola.entries.archive import write_contest_archive
from rola.entries.models import File, Submission


class ContestDownloadAdmin(ContestAdmin):
    """Contest configuration with a download of the contest's submissions."""

    fieldsets = [
        *ContestAdmin.fieldsets,
        ("Download", {"fields": ("download_action",)}),
    ]
    readonly_fields = ("download_action",)
    list_display = (*ContestAdmin.list_display, "download_action")

    def get_urls(self):
        """Add the contest download in front of the change view's catch-all URL."""
        download = path(
            "<int:contest_id>/download/",
            self.admin_site.admin_view(self.download_view),
            name="contests_contest_download",
        )
        return [download, *super().get_urls()]

    def download_view(self, request, contest_id):
        """Download all submissions of the contest as zip file.

        Only a superuser or the contest's owner may download it; the admin
        site already requires a staff login. The archive is as large as the
        contest's photographs together, so it is built in a temporary file
        instead of in memory.
        """
        contest = get_object_or_404(Contest, pk=contest_id)
        if not (request.user.is_superuser or contest.user_id == request.user.pk):
            return HttpResponseForbidden(
                "Only the organizer can download this contest."
            )

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

    @admin.display(description="Download")
    def download_action(self, obj):
        """Generate 'Download' button."""
        return format_html(
            '<a class="button" href="{}">Download</a>',
            reverse(f"{self.admin_site.name}:contests_contest_download", args=[obj.pk]),
        )


admin.site.register(Contest, ContestDownloadAdmin)
admin.site.register(Submission)
admin.site.register(File)
