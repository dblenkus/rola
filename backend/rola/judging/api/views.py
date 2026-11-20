"""Serve the rating, judging and results endpoints."""

from django.db.models import (
    CharField,
    Count,
    Exists,
    F,
    OuterRef,
    Prefetch,
    Q,
    Subquery,
    Sum,
    Value,
)
from django.db.models.functions import SHA1, Cast, Coalesce, Concat
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import mixins, permissions, viewsets

from rola.common.filters import OrderingFilter
from rola.contests.api.filters import ContestFilter
from rola.contests.models import Contest, Theme
from rola.entries.api.filters import SubmissionFilter
from rola.entries.models import Submission
from rola.judging.api.filters import RatingFilter
from rola.judging.api.permissions import CanModifyRating, IsActiveJudge
from rola.judging.api.serializers import (
    JudgeContestSerializer,
    JudgeSubmissionSerializer,
    RatingSerializer,
    SubmissionResultsSerializer,
    ThemeResultsSerializer,
)
from rola.judging.models import Judge, Rating
from rola.payments.models import PAID_SUBMISSION

# Results publish only entries in a paid submission set, as judging lists
# only those. Exists instead of a join, so an entry in several paid sets is
# listed once and its ratings are summed once.
IS_PAID = Exists(Submission.objects.filter(PAID_SUBMISSION, pk=OuterRef("pk")))


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
    serializer_class = JudgeSubmissionSerializer
    filterset_class = SubmissionFilter
    permission_classes = (IsActiveJudge,)

    def get_queryset(self):
        """Return queryset for submissions that can be shown to judge."""
        judge_qs = Judge.objects.filter(judge=self.request.user)
        theme_qs = Theme.objects.filter(contest__in=judge_qs.values("contest")).filter(
            contest__in=Contest.objects.in_judging()
        )
        return (
            Submission.objects.filter(PAID_SUBMISSION, theme__in=theme_qs)
            .annotate(
                random=SHA1(
                    Concat(Cast("pk", CharField()), Value(str(self.request.user.pk)))
                )
            )
            .order_by("random")
            .prefetch_related("files")
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
            Submission.objects.filter(PAID_SUBMISSION, theme=OuterRef("pk"))
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
        return (
            Contest.objects.filter(pk__in=judge_qs.values("contest"))
            .in_judging()
            .prefetch_related(Prefetch("themes", queryset=themes))
        )


class ThemeResultsViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Retrieve published results for a theme."""

    submission_qs = (
        Submission.objects.filter(IS_PAID)
        .annotate(rating_sum=Sum("rating__rating"))
        .select_related(
            "author",
            "author__user",
            "author__user__location",
            "author__reward",
        )
        .prefetch_related("files", "reward")
        .order_by("pk")
    )

    queryset = Theme.objects.select_related("contest").prefetch_related(
        Prefetch("submission_set", queryset=submission_qs)
    )
    serializer_class = ThemeResultsSerializer

    def get_queryset(self):
        """Return published themes that have results."""
        return self.queryset.filter(
            contest__in=Contest.objects.results_published(), results__isnull=False
        )


class SubmissionResultsViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    """List and retrieve accepted, paid submissions after publication."""

    queryset = (
        Submission.objects.filter(IS_PAID)
        .annotate(rating_sum=Sum("rating__rating"))
        .filter(rating_sum__gte=F("theme__results__accepted_threshold"))
        .select_related(
            "theme__contest",
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
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_class = SubmissionFilter
    ordering_fields = ["rating_sum"]

    def get_queryset(self):
        """Return accepted, paid submissions of published contests."""
        return self.queryset.filter(
            theme__contest__in=Contest.objects.results_published()
        )
