""".. Ignore pydocstyle D400.

==============
Core API views
==============

.. autoclass:: rolca.core.api.views.PhotoViewSet
    :members:

.. autoclass:: rolca.core.api.views.ContestViewSet
    :members:

"""
import logging

from django.db.models import Q
from django.utils import timezone

from rest_framework import exceptions, mixins, permissions, status, viewsets
from rest_framework.response import Response

from rolca.core.api.filters import (
    ContestFilter,
    InstitutionFilter,
    SubmissionFilter,
    SubmissionSetFilter,
)
from rolca.core.api.parsers import ImageUploadParser
from rolca.core.api.permissions import AdminOrReadOnly
from rolca.core.api.serializers import (
    AuthorSerializer,
    ContestSerializer,
    FileSerializer,
    InstitutionSerializer,
    SubmissionSerializer,
    SubmissionSetSerializer,
)
from rolca.core.models import (
    Author,
    Contest,
    File,
    Institution,
    Submission,
    SubmissionSet,
)

logger = logging.getLogger(__name__)


class FileViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """API viewset for File objects."""

    parser_classes = [ImageUploadParser]
    serializer_class = FileSerializer
    queryset = File.objects.none()
    permission_classes = (permissions.IsAuthenticated,)


class InstitutionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Institution.objects.all()
    serializer_class = InstitutionSerializer
    filterset_class = InstitutionFilter


class AuthorViewSet(viewsets.ModelViewSet):
    """API viewset for Author objects."""

    queryset = Author.objects.all()
    serializer_class = AuthorSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        queryset = self.queryset
        if self.request.user.is_superuser:
            return queryset

        return queryset.objects.filter(user=self.request.user)


class SubmissionViewSet(viewsets.ModelViewSet):
    """API view Submission objects."""

    serializer_class = SubmissionSerializer
    queryset = Submission.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    filterset_class = SubmissionFilter

    def get_queryset(self):
        """Return queryset for submissions that can be shown to user.

        Return:
        * all submissions for already finished contests
        * user's submissions

        """
        return Submission.objects.filter(
            Q(user__id=self.request.user.id)
            | Q(theme__contest__publish_date__lte=timezone.now())
        )

    def create(self, request):
        serializer_kwargs = {}
        if isinstance(request.data, list):
            serializer_kwargs['many'] = True

        serializer = self.get_serializer(data=request.data, **serializer_kwargs)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        instance = serializer.instance
        first_instance = instance[0] if isinstance(instance, list) else instance
        theme_ids = [submission['theme'] for submission in serializer.data]
        contest = Contest.objects.filter(themes__id__in=theme_ids).first()

        submission_set = SubmissionSet.objects.create(
            author=first_instance.author, user=first_instance.user, contest=contest
        )
        submission_set.submissions.add(
            *instance if isinstance(instance, list) else instance
        )

        if contest.confirmation_email and request.user.email:
            contest.confirmation_email.send(request.user.email)

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        if request.user != instance.user:
            raise exceptions.PermissionDenied(
                "You can only delete your own submissions."
            )
        if instance.theme.contest.publish_date < timezone.now():
            raise exceptions.PermissionDenied(
                "You cannot delete already published submissions."
            )

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class SubmissionSetViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    queryset = SubmissionSet.objects.all()
    serializer_class = SubmissionSetSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filterset_class = SubmissionSetFilter

    def get_queryset(self):
        """Return queryset for submissions that can be shown to user.

        Return:
        * all submissions for already finished contests
        * user's submissions

        """
        if self.request.user.is_superuser:
            return self.queryset

        return self.queryset.filter(user=self.request.user)

    def destroy(self, request, *args, **kwargs):
        """Destroy the instance and all related submissions."""
        instance = self.get_object()

        if instance.contest.publish_date < timezone.now():
            raise exceptions.PermissionDenied(
                "You cannot delete already published submission sets."
            )

        instance.submissions.all().delete()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ContestViewSet(viewsets.ModelViewSet):
    """API view Contest objects."""

    queryset = Contest.objects.all()
    serializer_class = ContestSerializer
    permission_classes = (AdminOrReadOnly,)
    filterset_class = ContestFilter
