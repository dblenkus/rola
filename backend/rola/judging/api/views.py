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
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.settings import api_settings

from rola.common.filters import OrderingFilter
from rola.contests.models import Contest, Theme
from rola.entries.models import Submission
from rola.judging import services
from rola.judging.api.filters import RatingFilter, SubmissionThemeFilter
from rola.judging.api.permissions import IsActiveJudge
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


class RatingViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List the caller's ratings and set the caller's rating of a submission."""

    queryset = Rating.objects.none()
    serializer_class = RatingSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filterset_class = RatingFilter
    # A judge rates a submission at most once, so the submission's id names
    # the caller's rating of it.
    lookup_field = "submission"
    # At most 18 digits, so the id fits a signed 64-bit integer in the query.
    lookup_value_regex = "[0-9]{1,18}"

    def get_queryset(self):
        """Restrict ratings to those of the caller's judges, as the PUT sets them."""
        return Rating.objects.filter(judge__judge=self.request.user).order_by("pk")

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "submission",
                int,
                OpenApiParameter.PATH,
                description="The id of the submission that the rating is for.",
            )
        ],
        responses={
            200: OpenApiResponse(
                RatingSerializer, description="The caller's rating, replaced."
            ),
            201: OpenApiResponse(
                RatingSerializer, description="The caller's rating, created."
            ),
        },
    )
    def update(self, request, *args, **kwargs):
        """Set the caller's rating of a submission, creating it if needed.

        Answers 201 when the rating is created and 200 when it existed, 404
        when the caller cannot rate the submission as a judge, and 403 once
        the contest's results are published.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rating, created = services.set_rating(
            request.user,
            int(self.kwargs[self.lookup_field]),
            serializer.validated_data["rating"],
        )
        return Response(
            self.get_serializer(rating).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "submission",
                int,
                OpenApiParameter.PATH,
                description="The id of the submission that the rating is for.",
            )
        ],
        responses={
            204: OpenApiResponse(
                description="The caller has no rating of the submission."
            ),
        },
    )
    def destroy(self, request, *args, **kwargs):
        """Clear the caller's rating of a submission, if there is one.

        Answers 204 whether or not the rating existed, and otherwise as the
        PUT: 404 when the caller cannot rate the submission as a judge, and
        403 once the contest's results are published.
        """
        services.clear_rating(request.user, int(self.kwargs[self.lookup_field]))
        return Response(status=status.HTTP_204_NO_CONTENT)


class JudgingSubmissionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List paid submissions assigned to an active judge."""

    queryset = Submission.objects.all()
    serializer_class = JudgeSubmissionSerializer
    filterset_class = SubmissionThemeFilter
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


class JudgingContestViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List contests assigned to the requesting judge."""

    queryset = Contest.objects.all()
    serializer_class = JudgeContestSerializer
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
                filter=Q(submission__rating__judge__judge=self.request.user),
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
        .annotate(score=Sum("rating__rating"))
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
        .annotate(score=Sum("rating__rating"))
        .filter(score__gte=F("theme__results__accepted_threshold"))
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
    filter_backends = [*api_settings.DEFAULT_FILTER_BACKENDS, OrderingFilter]
    filterset_class = SubmissionThemeFilter
    ordering_fields = ["score"]

    def get_queryset(self):
        """Return accepted, paid submissions of published contests."""
        return self.queryset.filter(
            theme__contest__in=Contest.objects.results_published()
        )
