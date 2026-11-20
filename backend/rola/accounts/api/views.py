"""Account management endpoints."""

from django.contrib.auth.hashers import check_password
from django.db import transaction
from django.db.models import ProtectedError
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import permissions, status, views, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.response import Response
from rest_framework.settings import api_settings

from rola.accounts.api.permissions import IsTargetUser
from rola.accounts.api.serializers import (
    LOGIN_FAILED_MESSAGE,
    ActivationSerializer,
    ChangePasswordSerializer,
    LoginSerializer,
    PasswordResetSerializer,
    RequestPasswordResetSerializer,
    TokenSerializer,
    UserRegistrationSerializer,
    UserSerializer,
    UserUpdateSerializer,
)
from rola.accounts.api.throttling import (
    ActivationThrottle,
    LoginThrottle,
    RecoveryThrottle,
    RegistrationThrottle,
)
from rola.accounts.models import Token, User
from rola.common.permissions import IsSuperUser


class Conflict(APIException):
    """Refuse a request that the current state of the data does not allow."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "The request conflicts with the current state of the data."
    default_code = "conflict"


class LoginView(views.APIView):
    """Issue a token for valid account credentials."""

    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    throttle_classes = [LoginThrottle]

    @extend_schema(request=LoginSerializer, responses=TokenSerializer)
    def post(self, request):
        """Validate credentials and return a token with its expiration."""
        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        with transaction.atomic():
            # A password change or reset expires only the tokens that already
            # exist, so issue one only while the row holds the checked
            # password. Its hash also changes when another login upgrades it,
            # so check the password again against the hash the row holds.
            locked = User.objects.select_for_update().get(pk=user.pk)
            if not locked.is_active or (
                locked.password != user.password
                and not check_password(
                    serializer.validated_data["password"], locked.password
                )
            ):
                raise ValidationError(
                    {api_settings.NON_FIELD_ERRORS_KEY: [LOGIN_FAILED_MESSAGE]},
                    code="authorization",
                )
            token = Token.objects.create_token(user=locked)
        return Response(TokenSerializer(token).data)


class LogoutView(views.APIView):
    """Expire the login token that the request presents."""

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=None, responses={204: None})
    def post(self, request):
        """Expire the caller's token, and no other, and answer without a body."""
        request.auth.expire()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema_view(
    list=extend_schema(
        description="List accounts visible to the caller.",
        parameters=[
            OpenApiParameter(
                "current",
                str,
                description="Any non-empty value limits the list "
                "to the caller's own account.",
            )
        ],
    ),
    # An empty security requirement marks registration as anonymous, which
    # drf-spectacular supports although its annotation lists names only.
    create=extend_schema(responses={201: None}, auth=[{}]),  # type: ignore[list-item]
    update=extend_schema(responses=UserSerializer),
    partial_update=extend_schema(responses=UserSerializer),
)
class UserViewSet(viewsets.ModelViewSet):
    """Manage the current account, with administrative access for superusers."""

    lookup_field = "id"
    lookup_value_regex = (
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    queryset = User.objects.select_related("location")
    serializer_class = UserSerializer
    permission_classes = [IsTargetUser | IsSuperUser]

    def get_serializer_class(self):
        """Use model validation for writes and nullable addresses for responses."""
        if self.action == "create":
            return UserRegistrationSerializer
        if self.action in {"update", "partial_update"}:
            return UserUpdateSerializer
        return super().get_serializer_class()

    def get_queryset(self):
        """Limit account visibility before object lookup or serialization."""
        user = self.request.user
        if not user.is_authenticated:
            return self.queryset.none()
        if self.request.query_params.get("current", False) or not user.is_superuser:
            return self.queryset.filter(pk=user.pk)
        return self.queryset

    def get_throttles(self):
        """Rate-limit password checks, registration and recovery by caller address."""
        if self.action == "change_password":
            return [LoginThrottle()]
        if self.action == "create":
            return [RegistrationThrottle()]
        if self.action == "activate_account":
            return [ActivationThrottle()]
        if self.action in {"request_password_reset", "password_reset"}:
            return [RecoveryThrottle()]
        return super().get_throttles()

    def create(self, request, *args, **kwargs):
        """Register an account, answering alike whether the address had one."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(status=status.HTTP_201_CREATED)

    def perform_destroy(self, instance):
        """Delete the account, or answer 409 while protected records refer to it."""
        try:
            super().perform_destroy(instance)
        except ProtectedError as error:
            raise Conflict(
                "This account cannot be deleted while other records depend on it."
            ) from error

    @extend_schema(request=ActivationSerializer, responses={200: None})
    @action(
        detail=False,
        methods=["post"],
        authentication_classes=[],
        permission_classes=[permissions.AllowAny],
    )
    def activate_account(self, request):
        """Activate an account using its email token."""
        serializer = ActivationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response()

    @extend_schema(request=ChangePasswordSerializer, responses={200: None})
    @action(detail=True, methods=["post"])
    def change_password(self, request, **kwargs):
        """Change the caller's password and expire previous tokens."""
        serializer = ChangePasswordSerializer(
            data=request.data, context={"user": self.get_object(), "request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response()

    @extend_schema(request=RequestPasswordResetSerializer, responses={200: None})
    @action(
        detail=False,
        methods=["post"],
        authentication_classes=[],
        permission_classes=[permissions.AllowAny],
    )
    def request_password_reset(self, request):
        """Request an account recovery email."""
        serializer = RequestPasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response()

    @extend_schema(request=PasswordResetSerializer, responses={200: None})
    @action(
        detail=False,
        methods=["post"],
        authentication_classes=[],
        permission_classes=[permissions.AllowAny],
    )
    def password_reset(self, request):
        """Consume a recovery token and set a new password."""
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response()
