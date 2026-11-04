"""Account management endpoints."""

from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import permissions, views, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Token, User
from .permissions import IsSuperUser, IsTargetUser
from .serializers import (
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
from .throttling import (
    ActivationThrottle,
    LoginThrottle,
    RecoveryThrottle,
    RegistrationThrottle,
)


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
        token = Token.objects.create_token(user=serializer.validated_data["user"])
        return Response(TokenSerializer(token).data)


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
    create=extend_schema(responses={201: UserSerializer}, auth=[{}]),
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
