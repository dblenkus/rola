"""Store contests, their themes and participating institutions."""

from datetime import datetime

from django.contrib import admin
from django.db import models
from django.db.models import Count, Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from rola.common.models import BaseModel


class ContestQuerySet(models.QuerySet):
    """Select contests by the dates that open and close each of their stages.

    The comparisons differ on purpose at the boundary instants, so each
    caller picks the rule by name rather than writing the dates again.
    """

    def active(self):
        """Return contests between their start and end dates, both included."""
        now = timezone.now()
        return self.filter(start_date__lte=now, end_date__gte=now)

    def inactive(self):
        """Return contests that have not started yet or have ended."""
        now = timezone.now()
        return self.exclude(start_date__lte=now, end_date__gte=now)

    def closed(self) -> ContestQuerySet:
        """Return contests whose entries are final.

        A contest closes after its end date, or when its results are
        published if that comes first. A contest that has not started yet is
        not closed.
        """
        now = timezone.now()
        return self.filter(Q(end_date__lt=now) | Q(publish_date__lte=now))

    def in_judging(self):
        """Return contests whose judging lists are open.

        The lists stay open up to and including the publish instant, unlike
        :meth:`results_unpublished`, which ends just before it.
        """
        return self.filter(publish_date__gte=timezone.now())

    def results_unpublished(self):
        """Return contests whose results are not published yet."""
        return self.filter(publish_date__gt=timezone.now())

    def results_published(self):
        """Return contests whose results are published."""
        return self.filter(publish_date__lte=timezone.now())


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

    objects = ContestQuerySet.as_manager()

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

    @admin.display(boolean=True, ordering="end_date", description=_("active"))
    def is_active(self):
        """Check if contest is active."""
        return self.start_date <= timezone.now() <= self.end_date

    def accepts_entries(self, now: datetime | None = None) -> bool:
        """Check whether entries may be created, changed or deleted.

        Entries close at the end date, or earlier if the results are
        published first.

        :param now: The moment to check, the current time by default.
        """
        if now is None:
            now = timezone.now()
        return self.start_date <= now <= self.end_date and now < self.publish_date

    def results_published(self):
        """Check whether the contest's results are published."""
        return self.publish_date <= timezone.now()

    @admin.display(description=_("number of submissons"))
    def number_of_photos(self):
        """Return number of photos submitted to the current contest."""
        return self.themes.aggregate(count=Count("submission"))["count"]


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
