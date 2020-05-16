from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.db.models import F

from rest_framework import exceptions, serializers

from .models import User, Token
from .utils.signing import (
    send_activation_email,
    send_reset_email,
    validate_activation_token,
    validate_reset_token,
)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'password', 'email', 'first_name', 'last_name']
        read_only_fields = ['id']
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'password': {'write_only': True},
        }

    def create(self, data):
        user = User.objects.create_user(
            email=data['email'],
            password=data['password'],
            first_name=data['first_name'],
            last_name=data['last_name'],
        )
        send_activation_email(user, self.context.get('request'))

        return user

    def validate_email(self, email):
        """Prevent updating the email."""
        if self.instance:
            return self.instance.email

        return email


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ['token', 'expires']

    token = serializers.CharField(source='key')


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'}, trim_whitespace=False
    )

    def validate(self, attrs):
        user = authenticate(
            request=self.context.get('request'),
            email=attrs.get('email'),
            password=attrs.get('password'),
        )
        if not user:
            raise serializers.ValidationError(
                'Unable to log in with provided credentials.', code='authorization'
            )

        attrs['user'] = user
        return attrs


class ActivationSerializer(serializers.Serializer):
    """Serializer for user account activation."""

    token = serializers.CharField()

    def validate(self, attrs):
        attrs['user'] = validate_activation_token(attrs['token'])
        return attrs

    def save(self):
        user = self.validated_data['user']

        user.is_active = True
        user.save()


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing the user password."""

    current_password = serializers.CharField()
    new_password = serializers.CharField()

    def validate_current_password(self, current_password):
        """Validate existing password."""
        user = self.context.get('user')
        if not user.check_password(current_password):
            raise serializers.ValidationError("Incorrect current password.")

        return current_password

    def validate_new_password(self, new_password):
        """Validate new password."""
        user = self.context.get('user')
        validate_password(new_password, user)

        return new_password

    def save(self):
        """Change the password."""
        user = self.context.get('user')
        user.set_password(self.validated_data['new_password'])
        user.save()

        Token.objects.expire_for_user(user)


class RequestPasswordResetSerializer(serializers.Serializer):
    """Serializer for requesting a password reset."""

    email = serializers.EmailField()

    def save(self):
        """Send the password reset email."""
        try:
            user = User.objects.get(email=self.validated_data['email'])
        except User.DoesNotExist:
            raise exceptions.NotFound("User does not exist.")

        send_reset_email(user, self.context.get('request'))


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset."""

    token = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, attrs):
        user = validate_reset_token(attrs['token'])
        attrs['user'] = user

        validate_password(attrs['new_password'], user)

        return attrs

    def save(self):
        user = self.validated_data['user']

        user.set_password(self.validated_data['new_password'])
        # Increment password reset counter (invalidates all previous tokens).
        user.password_reset_counter = F('password_reset_counter') + 1
        user.save()

        Token.objects.expire_for_user(user)
