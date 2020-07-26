"""User models."""
import binascii
import logging
import os
import uuid

from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.utils.timezone import now
from django.core.mail import send_mail
from django.db import models

from .settings import drf_user_settings

logger = logging.getLogger(__name__)


class UserManager(BaseUserManager):
    """Manager for User model."""

    def _create_user(self, email, password, **extra_fields):
        """Create and save a user with the given email, and password."""
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        validate_password(password, user)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create a user."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """Create a superuser."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class Email(models.Model):
    """E-mail model."""

    subject = models.CharField(max_length=100)

    body = models.TextField()

    html_body = models.TextField(null=True, blank=True)

    def send(self, address):
        """Send email to give address."""
        subject = ''.join(self.subject.splitlines())

        email_kwargs = {}
        if self.html_body:
            email_kwargs['html_message'] = self.html_body

        try:
            send_mail(subject, self.body, None, [address], **email_kwargs)
        except Exception:
            logger.exception(
                "Error while sending e-mail for user '{}'.".format(address)
            )


class Location(models.Model):
    """Location model."""

    address = models.CharField(max_length=100)

    city = models.CharField(max_length=100)

    postal_code = models.CharField(max_length=100)

    country = models.CharField(max_length=100)

    def __str__(self):
        """String representation of the object."""
        return f"{self.address}, {self.postal_code} {self.city}, {self.country}"


class User(AbstractBaseUser, PermissionsMixin):
    """User model."""

    internal_id = models.AutoField(primary_key=True)

    id = models.UUIDField(
        unique=True, default=uuid.uuid4, editable=False, db_index=True
    )

    email = models.EmailField(unique=True)

    first_name = models.CharField(max_length=150, null=True, blank=True)

    last_name = models.CharField(max_length=150, null=True, blank=True)

    location = models.ForeignKey(
        Location, on_delete=models.CASCADE, null=True, blank=True
    )

    is_staff = models.BooleanField(default=False)

    is_superuser = models.BooleanField(default=False)

    is_active = models.BooleanField(default=False)

    date_joined = models.DateTimeField(auto_now_add=True)

    password_reset_counter = models.IntegerField(default=0)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'

    class Meta:
        """User's meta options."""

        swappable = 'AUTH_USER_MODEL'
        ordering = ('internal_id',)

    def clean(self):
        """Clean the model."""
        super().clean()
        self.email = self.objects.normalize_email(self.email)

    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between."""
        return f'{self.first_name} {self.last_name}'.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name.strip()

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)


class TokenManager(models.Manager):
    """Manager for Token model."""

    def create_token(self, **kwargs):
        if 'expires' not in kwargs:
            kwargs['expires'] = now() + drf_user_settings.TOKEN_EXPIRES_SECONDS

        return self.create(**kwargs)

    def expire_for_user(self, user):
        """Expire all tokens for the given user."""
        self.filter(user=user).update(expires=now())


class Token(models.Model):
    """Authorization token model."""

    key = models.CharField(max_length=40, primary_key=True)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='auth_tokens', on_delete=models.CASCADE
    )

    created = models.DateTimeField(auto_now_add=True)

    expires = models.DateTimeField()

    objects = TokenManager()

    def save(self, *args, **kwargs):
        """Generate the key if it doesn't exist and save the model."""
        if not self.key:
            self.key = binascii.hexlify(os.urandom(20)).decode()
        return super().save(*args, **kwargs)

    @property
    def is_expired(self):
        return self.expires < now()

    def __str__(self):
        """Return string representation of the model."""
        return self.key
