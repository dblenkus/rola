"""Serve the account endpoints: login, logout, registration and recovery."""

from django.contrib.auth.hashers import check_password
from django.db import transaction
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.settings import api_settings

from rola.accounts.api.serializers import (
    LOGIN_FAILED_MESSAGE,
    ActivationSerializer,
    LoginSerializer,
    PasswordResetSerializer,
    RequestPasswordResetSerializer,
    TokenSerializer,
    UserRegistrationSerializer,
)
from rola.accounts.api.throttling import (
    ActivationThrottle,
    LoginThrottle,
    RecoveryThrottle,
    RegistrationThrottle,
)
from rola.accounts.models import Token, User


class AnonymousViewSet(viewsets.GenericViewSet):
    """Serve a request that needs no account, whatever credentials it carries.

    Without authentication classes a stale ``Authorization`` header cannot
    fail the request, and the schema lists an empty security requirement.
    """

    authentication_classes = []
    permission_classes = [permissions.AllowAny]


class TokenViewSet(AnonymousViewSet):
    """Issue login tokens, and expire the one a request presents."""

    serializer_class = LoginSerializer
    throttle_classes = [LoginThrottle]

    @extend_schema(responses={201: TokenSerializer})
    def create(self, request):
        """Issue a token for valid account credentials."""
        serializer = self.get_serializer(data=request.data)
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
        return Response(TokenSerializer(token).data, status=status.HTTP_201_CREATED)

    # The logout authenticates as every other endpoint does, and is throttled
    # only as they are, unlike the anonymous login.
    @extend_schema(request=None, responses={204: None})
    @action(
        detail=False,
        methods=["delete"],
        url_path="current",
        authentication_classes=api_settings.DEFAULT_AUTHENTICATION_CLASSES,
        permission_classes=[permissions.IsAuthenticated],
        throttle_classes=api_settings.DEFAULT_THROTTLE_CLASSES,
    )
    def current(self, request):
        """Expire the caller's token, and no other, and answer without a body."""
        request.auth.expire()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserViewSet(AnonymousViewSet):
    """Register accounts."""

    serializer_class = UserRegistrationSerializer
    throttle_classes = [RegistrationThrottle]

    @extend_schema(responses={202: None})
    def create(self, request):
        """Register an account, answering alike whether the address had one."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_202_ACCEPTED)


class ActivationViewSet(AnonymousViewSet):
    """Activate accounts with their email tokens."""

    serializer_class = ActivationSerializer
    throttle_classes = [ActivationThrottle]

    @extend_schema(responses={204: None})
    def create(self, request):
        """Activate the account that the token names."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class PasswordResetRequestViewSet(AnonymousViewSet):
    """Send password reset emails."""

    serializer_class = RequestPasswordResetSerializer
    throttle_classes = [RecoveryThrottle]

    @extend_schema(responses={202: None})
    def create(self, request):
        """Email a reset link to an active account, answering alike for any address."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_202_ACCEPTED)


class PasswordResetViewSet(AnonymousViewSet):
    """Set new passwords with reset tokens."""

    serializer_class = PasswordResetSerializer
    throttle_classes = [RecoveryThrottle]

    @extend_schema(responses={204: None})
    def create(self, request):
        """Consume a reset token and set the new password."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
