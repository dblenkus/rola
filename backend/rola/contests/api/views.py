"""Serve the contest and institution endpoints."""

from django.db.models import Count, Prefetch
from rest_framework import mixins, viewsets

from rola.contests.api.filters import ContestFilter
from rola.contests.api.serializers import ContestSerializer, InstitutionSerializer
from rola.contests.models import Contest, Institution, Theme


class InstitutionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List institutions."""

    queryset = Institution.objects.order_by("pk")
    serializer_class = InstitutionSerializer


class ContestViewSet(viewsets.ReadOnlyModelViewSet):
    """List and retrieve contests with their themes."""

    queryset = Contest.objects.all()
    serializer_class = ContestSerializer
    filterset_class = ContestFilter

    def get_queryset(self):
        """Load contest themes with their submission counts."""
        themes = Theme.objects.annotate(submission_count=Count("submission")).order_by(
            "pk"
        )
        return (
            super().get_queryset().prefetch_related(Prefetch("themes", queryset=themes))
        )
