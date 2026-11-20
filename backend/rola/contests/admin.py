"""Configure contests and their themes in the Django admin.

The contest download needs the entries, so :mod:`rola.entries.admin`
registers Contest with a subclass of :class:`ContestAdmin` that adds it.
"""

from django.contrib import admin

from rola.contests.models import Theme


class ThemeInline(admin.TabularInline):
    """Inline Theme tabular used in `ContestAdmin`."""

    model = Theme
    fields = ("title", "max_photos", "is_series")
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
            {"fields": ("date_of_birth_required", "club_required", "school_required")},
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
    ]

    inlines = [ThemeInline]

    list_display: tuple[str, ...] = (
        "title",
        "start_date",
        "end_date",
        "is_active",
        "number_of_photos",
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
