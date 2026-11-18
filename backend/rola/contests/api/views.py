""".. Ignore pydocstyle D400.

==================
Contests API views
==================

.. autoclass:: rola.contests.api.views.ContestViewSet
    :members:

"""

from django.db.models import Count, Prefetch
from rest_framework import mixins, viewsets

from rola.common.permissions import AdminOrReadOnly
from rola.contests.api.filters import ContestFilter, InstitutionFilter
from rola.contests.api.serializers import ContestSerializer, InstitutionSerializer
from rola.contests.models import Contest, Institution, Theme


class InstitutionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List institutions with optional filters."""

    queryset = Institution.objects.order_by("pk")
    serializer_class = InstitutionSerializer
    filterset_class = InstitutionFilter


class ContestViewSet(viewsets.ModelViewSet):
    """API view Contest objects."""

    queryset = Contest.objects.all()
    serializer_class = ContestSerializer
    permission_classes = (AdminOrReadOnly,)
    filterset_class = ContestFilter

    def get_queryset(self):
        """Load contest themes with their submission counts for reads."""
        queryset = super().get_queryset()
        if self.action not in ("list", "retrieve"):
            return queryset
        themes = Theme.objects.annotate(submission_count=Count("submission")).order_by(
            "pk"
        )
        return queryset.prefetch_related(Prefetch("themes", queryset=themes))
