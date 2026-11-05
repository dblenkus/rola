""".. Ignore pydocstyle D400."""

from django.db.models import (
    CharField,
    Count,
    F,
    OuterRef,
    Prefetch,
    Q,
    Subquery,
    Sum,
    Value,
)
from django.db.models.functions import SHA1, Cast, Coalesce, Concat
from django.utils import timezone
from rest_framework import mixins, permissions, viewsets

from rolca.core.api.filters import ContestFilter, SubmissionFilter
from rolca.core.api.querysets import with_submission_details
from rolca.core.api.serializers import SubmissionSerializer
from rolca.core.models import Contest, Submission, Theme
from rolca.rating.api.filters import RatingFilter
from rolca.rating.api.permissions import CanModifyRating, IsActiveJudge
from rolca.rating.api.serializers import (
    JudgeContestSerializer,
    RatingSerializer,
    SubmissionResultsSerializer,
    ThemeResultsSerializer,
)
from rolca.rating.models import Judge, Rating


class RatingViewSet(viewsets.ModelViewSet):
    """API viewset for Rating objects."""

    queryset = Rating.objects.none()
    serializer_class = RatingSerializer
    permission_classes = (permissions.IsAuthenticated, CanModifyRating)
    filterset_class = RatingFilter

    def get_queryset(self):
        """Restrict ratings to the requesting user."""
        return Rating.objects.filter(user=self.request.user).order_by("pk")


class SubmissionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List paid submissions assigned to an active judge."""

    queryset = Submission.objects.all()
    serializer_class = SubmissionSerializer
    filterset_class = SubmissionFilter
    permission_classes = (IsActiveJudge,)

    def get_queryset(self):
        """Return queryset for submissions that can be shown to judge."""
        judge_qs = Judge.objects.filter(judge=self.request.user)
        theme_qs = Theme.objects.filter(
            contest__in=judge_qs.values("contest"),
            contest__publish_date__gte=timezone.now(),
        )
        return with_submission_details(
            Submission.objects.filter(
                theme__in=theme_qs,
                submissionset__payment__paid=True,
            )
            .annotate(
                random=SHA1(
                    Concat(Cast("pk", CharField()), Value(str(self.request.user.pk)))
                )
            )
            .order_by("random")
        )


class ContestViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List contests assigned to the requesting judge."""

    queryset = Contest.objects.all()
    serializer_class = JudgeContestSerializer
    filterset_class = ContestFilter
    permission_classes = (IsActiveJudge,)

    def get_queryset(self):
        """Return queryset for contests that can be shown to judge."""
        judge_qs = Judge.objects.filter(judge=self.request.user)
        # A subquery keeps the payment join from multiplying the rating count.
        paid_counts = (
            Submission.objects.filter(
                theme=OuterRef("pk"), submissionset__payment__paid=True
            )
            .order_by()
            .values("theme")
            .annotate(total=Count("pk"))
            .values("total")
        )
        themes = Theme.objects.annotate(
            submission_count=Coalesce(Subquery(paid_counts), 0),
            rating_count=Count(
                "submission__rating",
                filter=Q(submission__rating__user=self.request.user),
            ),
        ).order_by("pk")
        return Contest.objects.filter(
            pk__in=judge_qs.values("contest"),
            publish_date__gte=timezone.now(),
        ).prefetch_related(Prefetch("themes", queryset=themes))


class ThemeResultsViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Retrieve published results for a theme."""

    submission_qs = (
        Submission.objects.annotate(rating_sum=Sum("rating__rating"))
        .select_related(
            "author",
            "author__user",
            "author__user__location",
            "author__reward",
        )
        .prefetch_related("files", "reward")
        .order_by("pk")
    )

    queryset = Theme.objects.prefetch_related(
        Prefetch("submission_set", queryset=submission_qs)
    )
    serializer_class = ThemeResultsSerializer

    def get_queryset(self):
        """Return published themes that have results."""
        return self.queryset.filter(
            contest__publish_date__lte=timezone.now(), results__isnull=False
        )


class SubmissionResultsViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    """List and retrieve accepted submissions after publication."""

    queryset = (
        Submission.objects.annotate(rating_sum=Sum("rating__rating"))
        .filter(rating_sum__gte=F("theme__results__accepted_threshold"))
        .select_related(
            "theme__results",
            "author",
            "author__user",
            "author__user__location",
            "author__reward",
        )
        .prefetch_related("files", "reward")
        .order_by("pk")
    )
    serializer_class = SubmissionResultsSerializer
    filterset_class = SubmissionFilter
    ordering_fields = ["rating_sum"]

    def get_queryset(self):
        """Return accepted submissions of published contests."""
        return self.queryset.filter(theme__contest__publish_date__lte=timezone.now())
