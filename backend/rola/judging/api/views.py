"""Serve the rating, judging and results endpoints."""

from django.db.models import (
    Case,
    CharField,
    Count,
    Exists,
    F,
    IntegerField,
    OuterRef,
    Prefetch,
    Q,
    Subquery,
    Sum,
    Value,
    When,
)
from django.db.models.functions import SHA1, Cast, Coalesce, Concat
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.response import Response

from rola.common.ids import ID_PATH_PATTERN
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
)
from rola.judging.models import Judge, Rating
from rola.payments.models import PAID_SUBMISSION

# Results publish only entries in a paid submission set, as judging lists
# only those. Exists instead of a join, so an entry in several paid sets is
# listed once and its ratings are summed once.
IS_PAID = Exists(Submission.objects.filter(PAID_SUBMISSION, pk=OuterRef("pk")))
# An entry is accepted when its rating total reaches its theme's threshold.
# A total of null, an entry without ratings, is never accepted.
IS_ACCEPTED = Q(rating_total__gte=F("theme__results__accepted_threshold"))


class RatingViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List the caller's ratings and set the caller's rating of a submission."""

    queryset = Rating.objects.none()
    serializer_class = RatingSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filterset_class = RatingFilter
    # A judge rates a submission at most once, so the submission's id names
    # the caller's rating of it.
    lookup_field = "submission"
    lookup_value_regex = ID_PATH_PATTERN

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


class SubmissionResultsViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    """List and retrieve the paid submissions of published theme results."""

    queryset = (
        Submission.objects.filter(IS_PAID, theme__results__isnull=False)
        .alias(rating_total=Sum("rating__rating"))
        .annotate(
            # Null unless accepted, so that a declined entry's total cannot
            # be read from the API, and the serializer derives acceptance
            # from it.
            score=Case(
                When(IS_ACCEPTED, then="rating_total"),
                default=None,
                output_field=IntegerField(),
            ),
        )
        .select_related(
            "theme__contest",
            "author",
            "author__user",
            "author__user__location",
            "author__reward",
        )
        .prefetch_related("files", "reward")
        .order_by("pk")
    )
    serializer_class = SubmissionResultsSerializer
    filterset_class = SubmissionThemeFilter

    def get_queryset(self):
        """Return paid submissions of published contests' theme results."""
        return self.queryset.filter(
            theme__contest__in=Contest.objects.results_published()
        )
