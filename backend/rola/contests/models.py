""".. Ignore pydocstyle D400.

===============
Contests models
===============

.. autoclass:: rola.contests.models.Contest
    :members:

.. autoclass:: rola.contests.models.Theme
    :members:

"""

from django.db import models
from django.db.models import Count
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from rola.common.models import BaseModel


class Contest(BaseModel):
    """Model for storing contests.

    Contest object is the main object of single contest. It can contain
    multiple themes and all important dates for contest (start, end and
    results date).
    """

    class Meta:
        """Contest Meta options."""

        ordering = ["id"]
        verbose_name = _("contest")
        verbose_name_plural = _("contests")

    #: title of the contest
    title = models.CharField(_("Title"), max_length=100)

    #: description of the contest
    description = models.TextField(_("Description"), null=True, blank=True)

    #: date when contest starts
    start_date = models.DateTimeField(_("Start date"))

    #: date when contest ends
    end_date = models.DateTimeField(_("End date"))

    #: date when results will be published
    publish_date = models.DateTimeField(_("Publish date"), blank=True)

    #: indicate if user must be logged-in to participate in contest
    login_required = models.BooleanField(_("Login required"), default=False)

    #: header image of the contest
    header_image = models.ImageField(null=True, blank=True)

    #: notice in HTML form
    notice_html = models.TextField(default="")

    #: confirmation in HTML form
    confirmation_html = models.TextField(default="")

    confirmation_email = models.ForeignKey(
        "accounts.Email", null=True, blank=True, on_delete=models.SET_NULL
    )

    dob_required = models.BooleanField(default=False)

    club_show = models.BooleanField(default=False)

    club_required = models.BooleanField(default=False)

    school_show = models.BooleanField(default=False)

    school_required = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        """Save Contest instance."""
        if not self.publish_date:
            self.publish_date = self.end_date

        super().save(*args, **kwargs)

    def __str__(self):
        """Return Contest's title."""
        return self.title

    def is_active(self):
        """Check if contest is active."""
        return self.start_date <= timezone.now() <= self.end_date

    is_active.admin_order_field = "end_date"
    is_active.boolean = True
    is_active.short_description = _("active")

    def accepts_entries(self, now=None):
        """Check whether entries may be created, changed or deleted.

        Entries close at the end date, or earlier if the results are
        published first.

        :param now: The moment to check, the current time by default.
        """
        if now is None:
            now = timezone.now()
        return self.start_date <= now <= self.end_date and now < self.publish_date

    def number_of_photos(self):
        """Return number of photos submitted to the current contest."""
        return self.themes.aggregate(count=Count("submission"))["count"]

    number_of_photos.short_description = _("number of submissons")


class Theme(BaseModel):
    """Model for storing themes."""

    class Meta:
        """Theme Meta options."""

        ordering = ["id"]
        verbose_name = _("theme")
        verbose_name_plural = _("themes")

    #: title of the theme
    title = models.CharField(_("Title"), max_length=100)

    #: contest that theme belongs to
    contest = models.ForeignKey(
        Contest, related_name="themes", on_delete=models.CASCADE
    )

    #: indicates whether the theme is a series or not
    is_series = models.BooleanField(default=False)

    #: number of photos that can be submited to theme
    n_photos = models.IntegerField(_("Number of photos"))

    def save(self, *args, **kwargs):
        """Save Theme instance."""
        if getattr(self, "user", None) is None:
            self.user = self.contest.user

        super().save(*args, **kwargs)

    def __str__(self):
        """Return theme's title."""
        return self.title


class Institution(BaseModel):
    """Store a participating institution."""

    SCHOOL = 1
    KIND_CHOICES = [
        (SCHOOL, "School"),
    ]

    kind = models.SmallIntegerField(choices=KIND_CHOICES)

    name = models.CharField(max_length=100)

    class Meta:
        """Keep institution names unique within each kind."""

        constraints = [
            models.UniqueConstraint(fields=["kind", "name"], name="unique_name_kind"),
        ]
