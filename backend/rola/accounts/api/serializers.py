"""Validate account and token API payloads."""

from functools import partial
from typing import Any

from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction
from drf_spectacular.utils import extend_schema_serializer
from rest_framework import serializers

from rola.accounts.models import Location, Token, User
from rola.accounts.services import change_password
from rola.accounts.utils.signing import (
    send_activation_email,
    send_existing_account_email,
    send_reset_email,
    validate_activation_token,
    validate_reset_token,
)

LOGIN_FAILED_MESSAGE = "Unable to log in with provided credentials."


class LocationSerializer(serializers.ModelSerializer):
    """Validate postal address fields against the location model."""

    class Meta:
        """Define the writable address fields."""

        model = Location
        fields = ["address", "city", "postal_code", "country"]


class NormalizedEmailField(serializers.EmailField):
    """Normalize email addresses before field validators check uniqueness."""

    def to_internal_value(self, data):
        """Parse the address using the account manager's normalization rules."""
        return User.objects.normalize_email(super().to_internal_value(data))


@extend_schema_serializer(component_name="User")
class UserRegistrationSerializer(serializers.ModelSerializer):
    """Validate a new account, including its required password."""

    serializer_field_mapping = {
        **serializers.ModelSerializer.serializer_field_mapping,
        models.EmailField: NormalizedEmailField,
    }

    class Meta:
        """Define the account fields, which precede the address fields."""

        model = User
        fields = ["password", "email", "first_name", "last_name"]
        extra_kwargs: dict[str, dict[str, Any]] = {
            "first_name": {"required": True},
            "last_name": {"required": True},
            "password": {"write_only": True, "trim_whitespace": False},
            # Without this, ModelSerializer adds a validator for the unique
            # email, whose error would tell which addresses have an account.
            "email": {"validators": []},
        }

    def get_fields(self):
        """Add the address fields, validated as the location model defines them."""
        fields = super().get_fields()
        for name, field in LocationSerializer().fields.items():
            field.source = f"location.{name}"
            fields[name] = field
        return fields

    def validate(self, attrs):
        """Run the configured password validators with the submitted account details."""
        user = User(
            **{key: attrs.get(key) for key in ("email", "first_name", "last_name")}
        )
        try:
            validate_password(attrs["password"], user)
        except ValidationError as error:
            raise serializers.ValidationError({"password": error.messages}) from error
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        """Create an inactive account, or email the account the address already has.

        Both paths hash the password and send one email after the transaction
        commits, so the response does not tell whether the address had an
        account. An existing address is looked up before any insert, because
        PostgreSQL logs a failed insert with the registrant's details. A
        registration racing another one for the same address meets the
        database's unique index instead and takes the existing-account path.
        """
        location_data = validated_data.pop("location")
        email = validated_data["email"]
        existing = User.objects.filter(email__iexact=email).first()
        if existing is not None:
            # The hash is discarded; computing it keeps the response time alike.
            make_password(validated_data["password"])
        else:
            try:
                with transaction.atomic():
                    location = Location.objects.create(**location_data)
                    user = User.objects.create_user(location=location, **validated_data)
            except IntegrityError:
                existing = User.objects.filter(email__iexact=email).first()
                if existing is None:
                    raise
            else:
                transaction.on_commit(partial(send_activation_email, user))
                return user
        transaction.on_commit(partial(send_existing_account_email, existing))
        return existing


class TokenSerializer(serializers.ModelSerializer):
    """Represent a newly issued token and its expiration."""

    token = serializers.CharField(source="key", read_only=True)

    class Meta:
        """Define the login response."""

        model = Token
        fields = ["token", "expires"]
        read_only_fields = ["expires"]


class LoginSerializer(serializers.Serializer):
    """Authenticate an active account."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate(self, attrs):
        """Verify credentials without revealing account existence."""
        user = authenticate(request=self.context.get("request"), **attrs)
        if not user:
            raise serializers.ValidationError(
                LOGIN_FAILED_MESSAGE, code="authorization"
            )
        attrs["user"] = user
        return attrs


class ActivationSerializer(serializers.Serializer):
    """Activate the account referenced by a signed token."""

    token = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """Require an unexpired token for an existing account."""
        validate_activation_token(attrs["token"])
        return attrs

    @transaction.atomic
    def save(self, **kwargs):
        """Activate the account unless an earlier use of the token already did."""
        user = validate_activation_token(self.validated_data["token"], lock=True)
        if not user.is_active:
            user.is_active = True
            user.save(update_fields=["is_active"])
        return user


class RequestPasswordResetSerializer(serializers.Serializer):
    """Request recovery without exposing whether an account exists."""

    email = serializers.EmailField()

    def save(self, **kwargs):
        """Send a recovery message only for an active account."""
        user = User.objects.filter(
            email__iexact=User.objects.normalize_email(self.validated_data["email"]),
            is_active=True,
        ).first()
        if user is not None:
            transaction.on_commit(partial(send_reset_email, user))
        return user


class PasswordResetSerializer(serializers.Serializer):
    """Validate a signed recovery token and replacement password."""

    token = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate(self, attrs):
        """Check the token and password policy before changing credentials."""
        user = validate_reset_token(attrs["token"])
        validate_password(attrs["new_password"], user)
        return attrs

    @transaction.atomic
    def save(self, **kwargs):
        """Consume the recovery token, activate the account and revoke its logins.

        The link reached the account's mailbox, which proves the address as
        well as an activation link does.
        """
        user = validate_reset_token(self.validated_data["token"], lock=True)
        change_password(user, self.validated_data["new_password"])
        if not user.is_active:
            user.is_active = True
            user.save(update_fields=["is_active"])
        return user
