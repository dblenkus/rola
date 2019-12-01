import logging

from rest_framework import exceptions, mixins, views, viewsets, permissions, status
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
    UserSerializer,
)

logger = logging.getLogger(__name__)


class LoginView(views.APIView):
    permission_classes = ()
    serializer_class = TokenSerializer

    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        token = Token.objects.create_token(user=user)

        return Response(self.serializer_class(token).data)


class UserViewSet(viewsets.ModelViewSet):
    """API view User model."""

    lookup_field = 'id'
    lookup_value_regex = (
        '[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}'
    )

    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsTargetUser | IsSuperUser]

    def get_queryset(self):
        """Return query sets."""
        user = self.request.user

        if self.request.query_params.get('current', False) or not user.is_superuser:
            return self.queryset.filter(pk=user.pk)

        return self.queryset

    @action(detail=False, methods=['post'])
    def activate_account(self, request):
        """Activate user account."""
        serializer = ActivationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response()

    @action(detail=True, methods=['post'])
    def change_password(self, request, **kwargs):
        """Change user password."""
        user = self.get_object()

        serializer = ChangePasswordSerializer(
            data=request.data, context={'user': user, 'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response()

    @action(detail=False, methods=['post'])
    def request_password_reset(self, request):
        """Request user password reset."""
        serializer = RequestPasswordResetSerializer(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response()

    @action(detail=False, methods=['post'])
    def password_reset(self, request):
        """Reset user password."""
        serializer = PasswordResetSerializer(
            data=request.data, context={'user': request.user}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response()

    # @action(detail=False, methods=['post'])
    # def validate_password(self, request):
    #     """Validate user password."""
    #     serializer = ValidatePasswordSerializer(data=request.data, context={'user': request.user})
    #     serializer.is_valid()

    #     return Response(serializer.errors)
