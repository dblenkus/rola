"""Serve the author, photograph, submission and submission set endpoints."""

import logging
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
from rola.entries.api.permissions import IsSubmissionOwnerOrReadOnly
from rola.entries.api.querysets import with_submission_details
from rola.entries.api.serializers import (
    AuthorSerializer,
    FileSerializer,
    SubmissionSerializer,
    SubmissionSetSerializer,
    SubmissionWriteSerializer,
)
from rola.entries.models import Author, File, Submission, SubmissionSet

logger = logging.getLogger(__name__)


def _component(name):
    """Return a reference to a component of the generated API schema."""
    return {"$ref": f"#/components/schemas/{name}"}


def _one_or_many(name):
    """Describe a body that holds one component object or a list of them."""
    return {"oneOf": [_component(name), {"type": "array", "items": _component(name)}]}


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
    """API viewset for File objects."""

    parser_classes = [ImageUploadParser]
    serializer_class = FileSerializer
    queryset = File.objects.none()
    permission_classes = (permissions.IsAuthenticated,)


class AuthorViewSet(viewsets.ModelViewSet):
    """API viewset for Author objects."""

    queryset = Author.objects.all()
    serializer_class = AuthorSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        """Restrict authors to their owner unless the requester is an administrator."""
        queryset = self.queryset
        if self.action in ("list", "retrieve"):
            queryset = queryset.select_related("user")
        if self.request.user.is_superuser:
            return queryset

        return queryset.filter(user=self.request.user)

    def perform_update(self, serializer):
        """Refuse to change an author with entries in a closed contest."""
        self._refuse_closed_entries(serializer.instance)
        super().perform_update(serializer)

    def perform_destroy(self, instance):
        """Refuse to delete an author with entries in a closed contest."""
        self._refuse_closed_entries(instance)
        super().perform_destroy(instance)

    def _refuse_closed_entries(self, author):
        """Keep the entries that judging and results show unchanged.

        Deleting an author deletes its submissions and their photographs,
        and the results show the author's name.
        """
        services.refuse_closed_entries(author.submission_set.all())


@extend_schema_view(
    # SubmissionSerializer reads the request method, so the schema generator
    # cannot instantiate it here; SubmissionRequest is its request component,
    # which update registers.
    create=extend_schema(
        parameters=[
            OpenApiParameter(
                "Idempotency-Key",
                OpenApiTypes.UUID,
                OpenApiParameter.HEADER,
                description="Identifies the upload, so that a retry after a lost "
                "response returns the submissions instead of entering them again.",
            )
        ],
        request={
            "application/json": _one_or_many("SubmissionRequest"),
        },
        responses={
            200: OpenApiResponse(
                _one_or_many("SubmissionWrite"),
                description="The submissions of the requester's earlier upload "
                "with this Idempotency-Key; a list when the request body is a list.",
            ),
            201: OpenApiResponse(
                _one_or_many("SubmissionWrite"),
                description="A list when the request body is a list.",
            ),
        },
    ),
    update=extend_schema(responses=SubmissionWriteSerializer),
    partial_update=extend_schema(responses=SubmissionWriteSerializer),
)
class SubmissionViewSet(viewsets.ModelViewSet):
    """API view Submission objects."""

    serializer_class = SubmissionSerializer
    queryset = Submission.objects.all()
    permission_classes = (permissions.IsAuthenticated, IsSubmissionOwnerOrReadOnly)
    filterset_class = SubmissionFilter

    def get_queryset(self):
        """Return the requester's own submissions.

        Published submissions of other accounts are available only through
        the results endpoints, which show public author details and only the
        photographs of accepted submissions.
        """
        queryset = Submission.objects.filter(user=self.request.user)
        if self.action in ("list", "retrieve"):
            return with_submission_details(queryset)
        return queryset

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        """Create one coherent submission set, atomically, for either payload shape.

        A request that repeats the Idempotency-Key of the requester's earlier
        upload creates nothing and returns that upload's submissions. Once all
        of them are deleted, the request is entered as a new upload.
        """
        services.lock_account(request.user)
        upload_key = self._upload_key()
        if upload_key is not None:
            uploaded = services.find_upload(request.user, upload_key)
            # Answered before validation: the photographs of a repeated request
            # may be attached by now, and its contest may have closed.
            if uploaded is not None:
                data = self.get_serializer(
                    uploaded.submissions.order_by("pk"), many=True
                ).data
                return Response(
                    data if isinstance(request.data, list) else data[0],
                    status=status.HTTP_200_OK,
                )

        many = isinstance(request.data, list)
        serializer_kwargs = {"many": True, "allow_empty": False} if many else {}
        serializer = self.get_serializer(data=request.data, **serializer_kwargs)
        serializer.is_valid(raise_exception=True)
        items = serializer.validated_data if many else [serializer.validated_data]
        submissions = services.enter_submissions(request.user, items, upload_key)

        data = self.get_serializer(
            submissions if many else submissions[0], many=many
        ).data
        headers = self.get_success_headers(data)
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)

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

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        """Serialize file reassignment with other submission writes."""
        services.lock_account(request.user)
        return super().update(request, *args, **kwargs)

    def perform_update(self, serializer):
        """Limit the theme's photographs and lock uploads before saving."""
        instance = serializer.instance
        data = serializer.validated_data
        if "files" in data or "theme" in data:
            count = len(data["files"]) if "files" in data else instance.files.count()
            theme = data.get("theme", instance.theme)
            services.limit_photos(instance.author, theme, count, instance)
        if "files" in data:
            services.lock_files(self.request.user, data["files"], instance.pk)
        serializer.save()

    def destroy(self, request, *args, **kwargs):
        """Delete the requester's submission while its contest accepts entries."""
        instance = self.get_object()

        if request.user != instance.user:
            raise exceptions.PermissionDenied(
                "You can only delete your own submissions."
            )
        services.require_open_contest(instance.theme.contest)

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class SubmissionSetViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """List and delete the requesting user's submission sets."""

    queryset = SubmissionSet.objects.all()
    serializer_class = SubmissionSetSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filterset_class = SubmissionSetFilter

    def get_queryset(self):
        """Load the requester's submission sets, or all sets for administrators."""
        queryset = self.queryset
        if not self.request.user.is_superuser:
            queryset = queryset.filter(user=self.request.user)
        if self.action in ("list", "retrieve"):
            queryset = queryset.select_related("author__user").prefetch_related(
                Prefetch(
                    "submissions",
                    queryset=with_submission_details(Submission.objects.all()),
                )
            )
        return queryset

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
