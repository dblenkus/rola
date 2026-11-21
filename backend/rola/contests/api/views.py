"""Serve the contest and institution endpoints."""

from rest_framework import mixins, viewsets

from rola.contests.api.filters import ContestFilter
from rola.contests.api.serializers import ContestSerializer, InstitutionSerializer
from rola.contests.models import Contest, Institution


class InstitutionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List institutions."""

    queryset = Institution.objects.order_by("pk")
    serializer_class = InstitutionSerializer


class ContestViewSet(viewsets.ReadOnlyModelViewSet):
    """List and retrieve contests with their themes."""

    queryset = Contest.objects.prefetch_related("themes")
    serializer_class = ContestSerializer
    filterset_class = ContestFilter
