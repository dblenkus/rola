"""Serve the author, photograph, submission and submission set endpoints."""

import uuid

from django.db import transaction
from django.db.models import Prefetch
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import exceptions, mixins, permissions, status, viewsets
from rest_framework.response import Response

from rola.entries import services
from rola.entries.api.filters import SubmissionFilter, SubmissionSetFilter
from rola.entries.api.parsers import ImageUploadParser
from rola.entries.api.querysets import with_submission_details
from rola.entries.api.serializers import (
    AuthorSerializer,
    FileSerializer,
    SubmissionSerializer,
    SubmissionSetCreateSerializer,
    SubmissionSetSerializer,
)
from rola.entries.models import Author, File, Submission, SubmissionSet


@extend_schema_view(
    create=extend_schema(
        request={"image/jpeg": OpenApiTypes.BINARY},
        parameters=[
            OpenApiParameter(
                "Content-Disposition",
                str,
                OpenApiParameter.HEADER,
                required=True,
                description="Names the photograph, for example "
                'attachment; filename="photo.jpg".',
            )
        ],
    )
)
class FileViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """Upload a photograph for a later submission."""

    parser_classes = [ImageUploadParser]
    serializer_class = FileSerializer
    queryset = File.objects.none()
    permission_classes = (permissions.IsAuthenticated,)


class AuthorViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """Create an author of the requester's submissions."""

    queryset = Author.objects.none()
    serializer_class = AuthorSerializer
    permission_classes = (permissions.IsAuthenticated,)


class SubmissionViewSet(
    mixins.ListModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet
):
    """List and delete the requester's own submissions."""

    serializer_class = SubmissionSerializer
    queryset = Submission.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    filterset_class = SubmissionFilter

    def get_queryset(self):
        """Return the requester's own submissions.

        Published submissions of other accounts are available only through
        the results endpoints, which show public author details and only the
        photographs of accepted submissions.
        """
        queryset = Submission.objects.filter(user=self.request.user)
        if self.action == "list":
            return with_submission_details(queryset)
        return queryset

    def perform_destroy(self, instance):
        """Delete the submission while its contest accepts entries."""
        services.require_open_contest(instance.theme.contest)
        instance.delete()


class SubmissionSetViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """Upload, list and delete the requester's submission sets."""

    queryset = SubmissionSet.objects.all()
    serializer_class = SubmissionSetSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filterset_class = SubmissionSetFilter

    def get_queryset(self):
        """Load the requester's submission sets, or all sets for administrators."""
        queryset = self.queryset
        if not self.request.user.is_superuser:
            queryset = queryset.filter(user=self.request.user)
        if self.action in ("list", "retrieve", "create"):
            queryset = queryset.select_related("author__user").prefetch_related(
                Prefetch(
                    "submissions",
                    queryset=with_submission_details(Submission.objects.all()),
                )
            )
        return queryset

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "Idempotency-Key",
                OpenApiTypes.UUID,
                OpenApiParameter.HEADER,
                description="Identifies the upload, so that a retry after a lost "
                "response returns the submission set instead of entering it again.",
            )
        ],
        request=SubmissionSetCreateSerializer,
        responses={
            200: OpenApiResponse(
                SubmissionSetSerializer,
                description="The set of the requester's earlier upload with this "
                "Idempotency-Key.",
            ),
            201: SubmissionSetSerializer,
        },
    )
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        """Enter an upload's submissions and their set atomically.

        A request that repeats the Idempotency-Key of the requester's earlier
        upload creates nothing and returns that upload's set. Once all of its
        submissions are deleted, the request is entered as a new upload.
        """
        services.lock_account(request.user)
        upload_key = self._upload_key()
        if upload_key is not None:
            uploaded = services.find_upload(request.user, upload_key)
            # Answered before validation: the photographs of a repeated request
            # may be attached by now, and its contest may have closed.
            if uploaded is not None:
                return Response(self._represent(uploaded), status=status.HTTP_200_OK)

        serializer = SubmissionSetCreateSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        submission_set = services.enter_submissions(
            request.user,
            serializer.validated_data["author"],
            serializer.validated_data["submissions"],
            upload_key,
        )
        return Response(self._represent(submission_set), status=status.HTTP_201_CREATED)

    def _upload_key(self):
        """Return the request's Idempotency-Key, or ``None`` without one.

        :raises ParseError: If the header is not a UUID.
        """
        value = self.request.headers.get("Idempotency-Key")
        if value is None:
            return None
        try:
            return uuid.UUID(value)
        except ValueError as error:
            raise exceptions.ParseError(
                "The Idempotency-Key header must be a UUID."
            ) from error

    def _represent(self, submission_set):
        """Serialize the set as reading it answers."""
        return self.get_serializer(self.get_queryset().get(pk=submission_set.pk)).data

    def destroy(self, request, *args, **kwargs):
        """Delete a set and its submissions while its contest accepts entries.

        Superusers may delete any set until the results are published.
        """
        instance = self.get_object()

        # Organizers remove duplicate and mistaken sets here, as the Django
        # admin does not list submission sets.
        if not (request.user.is_superuser and not instance.contest.results_published()):
            services.require_open_contest(instance.contest)

        instance.submissions.all().delete()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
