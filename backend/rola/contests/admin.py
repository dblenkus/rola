""".. Ignore pydocstyle D400.

==========
Core Admin
==========

.. autoclass:: rola.contests.admin.ThemeInline
    :members:

.. autoclass:: rola.contests.admin.ContestAdmin
    :members:

"""

from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html

from rola.contests.models import Contest, File, Submission, Theme


class ThemeInline(admin.TabularInline):
    """Inline Theme tabular used in `ContestAdmin`."""

    model = Theme
    fields = ("title", "n_photos", "is_series")
    extra = 1


class ContestAdmin(admin.ModelAdmin):
    """Contest configuration."""

    fieldsets_new = [
        (None, {"fields": ("title", "description")}),
        ("Dates", {"fields": ("start_date", "end_date", "publish_date")}),
        ("Details", {"fields": ("header_image", "notice_html", "confirmation_email")}),
    ]
    fieldsets = [
        (None, {"fields": ("title", "description")}),
        ("Dates", {"fields": ("start_date", "end_date", "publish_date")}),
        (
            "Author informations",
            {"fields": ("dob_required", "club_required", "school_required")},
        ),
        (
            "Details",
            {
                "fields": (
                    "header_image",
                    "notice_html",
                    "confirmation_html",
                    "confirmation_email",
                )
            },
        ),
        ("Download", {"fields": ("download_action",)}),
    ]
    readonly_fields = ("download_action",)

    inlines = [ThemeInline]

    list_display = (
        "title",
        "start_date",
        "end_date",
        "is_active",
        "number_of_photos",
        "download_action",
    )
    list_filter = ["start_date", "end_date", "publish_date"]
    search_fields = ["title"]

    def save_model(self, request, obj, form, change):
        """Add current user to the model and save it."""
        if getattr(obj, "user", None) is None:
            obj.user = request.user
        obj.save()

    def get_fieldsets(self, request, obj=None):
        """Return different fieldset for new and existing objects."""
        if obj:
            return self.fieldsets

        return self.fieldsets_new

    def download_action(self, obj):
        """Generate 'Download' button."""
        return format_html(
            '<a class="button" href="{}">Download</a>',
            reverse("contests:download-contest", args=[obj.pk]),
        )

    download_action.short_description = "Download"
    download_action.allow_tags = True


admin.site.register(Contest, ContestAdmin)
admin.site.register(Submission)
admin.site.register(File)
