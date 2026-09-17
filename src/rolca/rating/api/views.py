""".. Ignore pydocstyle D400."""
from django.db.models import F, Prefetch, Sum, Value
from django.db.models.functions import SHA1, Concat
from django.utils import timezone
from rest_framework import mixins, permissions, viewsets

from rolca.core.api.serializers import SubmissionSerializer
from rolca.core.api.filters import ContestFilter, SubmissionFilter
from rolca.core.models import Author, Contest, Submission, Theme
from rolca.rating.api.filters import RatingFilter
from rolca.rating.api.permissions import IsActiveJudge
from rolca.rating.api.serializers import (
    ContestSerializer,
    RatingSerializer,
    SubmissionResultsSerializer,
    ThemeResultsSerializer,
)
from rolca.rating.models import Judge, Rating


class RatingViewSet(viewsets.ModelViewSet):
    """API viewset for Rating objects."""

    queryset = Rating.objects.none()
    serializer_class = RatingSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filterset_class = RatingFilter

    def get_queryset(self):
        return Rating.objects.filter(user=self.request.user)


class SubmissionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Submission.objects.all()
    serializer_class = SubmissionSerializer
    filterset_class = SubmissionFilter
    permission_classes = (IsActiveJudge,)

    def get_queryset(self):
        """Return queryset for submissions that can be shown to judge."""
        judge_qs = Judge.objects.filter(judge=self.request.user)
        theme_qs = Theme.objects.filter(
            contest__in=judge_qs.values('contest'),
            contest__publish_date__gte=timezone.now(),
        )
        return (
            Submission.objects.filter(
                theme__in=theme_qs,
                submissionset__payment__paid=True,
            )
            .annotate(random=SHA1(Concat("pk", Value(str(self.request.user.pk)))))
            .order_by("random")
        )


class ContestViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Contest.objects.all()
    serializer_class = ContestSerializer
    filterset_class = ContestFilter
    permission_classes = (IsActiveJudge,)

    def get_queryset(self):
        """Return queryset for contests that can be shown to judge."""
        judge_qs = Judge.objects.filter(judge=self.request.user)
        return Contest.objects.filter(
            pk__in=judge_qs.values('contest'),
            publish_date__gte=timezone.now(),
        )


class ThemeResultsViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    submission_qs = (
        Submission.objects.annotate(rating_sum=Sum('rating__rating'))
        .select_related(
            'author',
            'author__user',
            'author__user__location',
            'author__reward',
        )
        .prefetch_related('files', 'reward')
    )

    queryset = Theme.objects.prefetch_related(
        Prefetch('submission_set', queryset=submission_qs)
    )
    serializer_class = ThemeResultsSerializer

    def get_queryset(self):
        """Return queryset of published themes."""
        return self.queryset.filter(contest__publish_date__lte=timezone.now())


class SubmissionResultsViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    author_qs = Author.objects.select_related('user', 'user__location', 'reward')

    queryset = (
        Submission.objects.annotate(rating_sum=Sum('rating__rating'))
        .filter(rating_sum__gte=F('theme__results__accepted_threshold'))
        .select_related(
            'theme__results',
            'author',
            'author__user',
            'author__user__location',
            'author__reward',
        )
        .prefetch_related('files', 'reward')
    )
    serializer_class = SubmissionResultsSerializer
    filterset_class = SubmissionFilter
    ordering_fields = ['rating_sum']

    def get_queryset(self):
        """Return queryset of published themes."""
        return self.queryset.filter(theme__contest__publish_date__lte=timezone.now())
