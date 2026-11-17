""".. Ignore pydocstyle D400.

==============
Core API views
==============

.. autoclass:: rolca.core.api.views.FileViewSet
    :members:

.. autoclass:: rolca.core.api.views.ContestViewSet
    :members:

"""

import logging
import uuid
from collections import Counter
from functools import partial

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Count, Prefetch, Q
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import exceptions, mixins, permissions, status, viewsets
from rest_framework.response import Response

from rolca.core.api.filters import (
    ContestFilter,
    InstitutionFilter,
    SubmissionFilter,
    SubmissionSetFilter,
)
from rolca.core.api.parsers import ImageUploadParser
from rolca.core.api.permissions import (
    AdminOrReadOnly,
    IsSubmissionOwnerOrReadOnly,
    require_open_contest,
)
from rolca.core.api.querysets import with_submission_details
from rolca.core.api.serializers import (
    AuthorSerializer,
    ContestSerializer,
    FileSerializer,
    InstitutionSerializer,
    SubmissionSerializer,
    SubmissionSetSerializer,
    SubmissionWriteSerializer,
)
from rolca.core.models import (
    Author,
    Contest,
    File,
    Institution,
    Submission,
    SubmissionSet,
    Theme,
)

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


class InstitutionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List institutions with optional filters."""

    queryset = Institution.objects.order_by("pk")
    serializer_class = InstitutionSerializer
    filterset_class = InstitutionFilter


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
        now = timezone.now()
        # Publishing the results closes the entries before the end date.
        closed = author.submission_set.filter(
            Q(theme__contest__end_date__lt=now)
            | Q(theme__contest__publish_date__lte=now)
        )
        if closed.exists():
            raise exceptions.PermissionDenied(
                "Entries in a closed contest can no longer be changed."
            )


@extend_schema_view(
    # SubmissionSerializer reads the request method, so the schema generator
    # cannot instantiate it here; SubmissionRequest is its request component,
    # which update registers. A form body cannot hold a list.
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
            "application/x-www-form-urlencoded": _component("SubmissionRequest"),
            "multipart/form-data": _component("SubmissionRequest"),
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
        self._lock_account()
        upload_key = self._upload_key()
        if upload_key is not None:
            uploaded = SubmissionSet.objects.filter(
                user=request.user, upload_key=upload_key
            ).first()
            if uploaded is not None and not uploaded.submissions.exists():
                # Deleting submissions keeps their set, which a payment may
                # refer to, so an empty set means the earlier upload was
                # withdrawn: this request is entered anew, and its set takes
                # over the key.
                SubmissionSet.objects.filter(pk=uploaded.pk).update(upload_key=None)
                uploaded = None
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

        serializer_kwargs = {}
        if isinstance(request.data, list):
            serializer_kwargs.update(many=True, allow_empty=False)

        serializer = self.get_serializer(data=request.data, **serializer_kwargs)
        serializer.is_valid(raise_exception=True)
        items = (
            serializer.validated_data
            if serializer_kwargs
            else [serializer.validated_data]
        )
        contest = items[0]["theme"].contest
        if any(item["theme"].contest_id != contest.pk for item in items):
            raise exceptions.ValidationError(
                "All submissions must belong to the same contest."
            )
        require_open_contest(contest)
        if any(item["author"] != items[0]["author"] for item in items):
            raise exceptions.ValidationError(
                "All submissions must have the same author."
            )
        files = [file for item in items for file in item["files"]]
        if len({file.pk for file in files}) != len(files):
            raise exceptions.ValidationError(
                "Each file may only be used once in a submission set."
            )
        new_photos = Counter()
        for item in items:
            new_photos[item["theme"]] += len(item["files"])
        for theme, count in new_photos.items():
            self._limit_photos(items[0]["author"], theme, count)
        self._lock_files(files)
        self.perform_create(serializer)

        instances = serializer.instance if serializer_kwargs else [serializer.instance]
        first_instance = instances[0]

        submission_set = SubmissionSet.objects.create(
            author=first_instance.author,
            user=first_instance.user,
            contest=contest,
            upload_key=upload_key,
        )
        submission_set.submissions.add(*instances)

        if contest.confirmation_email and request.user.email:
            transaction.on_commit(
                partial(contest.confirmation_email.send, request.user.email),
                robust=True,
            )

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

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

    def _lock_account(self):
        """Serialize the requester's submission writes.

        Concurrent writes would otherwise each count the photographs in a
        theme without the ones that the other is adding.
        """
        get_user_model().objects.select_for_update().get(pk=self.request.user.pk)

    def _limit_photos(self, author, theme, count, submission=None):
        """Refuse more than the theme's number of photographs per author.

        The limit counts photographs, not submissions: a series is one
        submission with up to that many photographs.
        """
        entered = File.objects.filter(
            submission__author=author, submission__theme=theme
        )
        if submission is not None:
            entered = entered.exclude(submission=submission)
        if entered.count() + count > theme.n_photos:
            raise exceptions.ValidationError(
                {
                    "files": [
                        f'Too many photographs for the theme "{theme.title}", '
                        f"which accepts {theme.n_photos} per author."
                    ]
                }
            )

    def _lock_files(self, files, submission=None):
        """Recheck attachment state under a lock to prevent concurrent file reuse."""
        locked = list(
            File.objects.select_for_update()
            .filter(pk__in=[file.pk for file in files])
            .order_by("pk")
        )
        if len(locked) != len(files) or any(
            file.user_id != self.request.user.pk
            or file.submission_id not in (None, submission)
            for file in locked
        ):
            raise exceptions.ValidationError(
                {"files": "An upload is no longer available."}
            )

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        """Serialize file reassignment with other submission writes."""
        self._lock_account()
        return super().update(request, *args, **kwargs)

    def perform_update(self, serializer):
        """Limit the theme's photographs and lock uploads before saving."""
        instance = serializer.instance
        data = serializer.validated_data
        if "files" in data or "theme" in data:
            count = len(data["files"]) if "files" in data else instance.files.count()
            theme = data.get("theme", instance.theme)
            self._limit_photos(instance.author, theme, count, instance)
        if "files" in data:
            self._lock_files(data["files"], instance.pk)
        serializer.save()

    def destroy(self, request, *args, **kwargs):
        """Delete the requester's submission while its contest accepts entries."""
        instance = self.get_object()

        if request.user != instance.user:
            raise exceptions.PermissionDenied(
                "You can only delete your own submissions."
            )
        require_open_contest(instance.theme.contest)

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
        if not (
            request.user.is_superuser and timezone.now() < instance.contest.publish_date
        ):
            require_open_contest(instance.contest)

        instance.submissions.all().delete()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


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
