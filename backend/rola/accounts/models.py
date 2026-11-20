"""User models."""

import hashlib
import logging
import secrets
import uuid

from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.db import models
from django.db.models.functions import Lower
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils.timezone import now

from .settings import accounts_settings

logger = logging.getLogger(__name__)

# Every login token starts with this; the authenticator refuses any other string.
TOKEN_PREFIX = "rola_st_"


def token_digest(token: str) -> str:
    """Return the SHA-256 hex digest that the database stores for a token."""
    return hashlib.sha256(token.encode()).hexdigest()


class UserManager(BaseUserManager["User"]):
    """Manager for User model."""

    @classmethod
    def normalize_email(cls, email: str | None) -> str:
        """Lowercase the address without changing dots or plus tags."""
        return super().normalize_email(email).lower()

    def get_by_natural_key(self, username: str | None) -> User:
        """Find an account independently of email capitalization."""
        return self.get(email__iexact=self.normalize_email(username))

    def _create_user(self, email, password, **extra_fields):
        """Create and save a user with the given email, and password."""
        if not email:
            raise ValueError("An email address is required.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password is not None:
            validate_password(password, user)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create a user."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """Create a superuser."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, password, **extra_fields)


class Email(models.Model):
    """E-mail model."""

    subject = models.CharField(max_length=100)

    body = models.TextField()

    html_body = models.TextField(null=True, blank=True)

    def send(self, address):
        """Send email to give address."""
        subject = "".join(self.subject.splitlines())

        email_kwargs = {}
        if self.html_body:
            email_kwargs["html_message"] = self.html_body

        try:
            send_mail(subject, self.body, None, [address], **email_kwargs)
        except Exception as error:
            logger.error("Unable to send contest email (%s).", type(error).__name__)


class Location(models.Model):
    """Location model."""

    address = models.CharField(max_length=100)

    city = models.CharField(max_length=100)

    postal_code = models.CharField(max_length=100)

    country = models.CharField(max_length=100)

    def __str__(self):
        """Return the street, postal code, city and country on one line."""
        return f"{self.address}, {self.postal_code} {self.city}, {self.country}"


class User(AbstractBaseUser, PermissionsMixin):
    """User model."""

    internal_id = models.BigAutoField(primary_key=True)

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

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "email"

    class Meta:
        """User's meta options."""

        swappable = "AUTH_USER_MODEL"
        ordering = ("internal_id",)
        constraints = [
            models.UniqueConstraint(Lower("email"), name="accounts_email_ci_unique")
        ]

    def clean(self):
        """Clean the model."""
        super().clean()
        self.email = type(self).objects.normalize_email(self.email)

    def check_password(self, raw_password: str | None) -> bool:
        """Check the password and upgrade an outdated hash that is still stored.

        Django saves the upgraded hash over the row, which would restore the
        old password over a reset or change that committed after this
        instance was loaded.
        """
        checked_hash = self.password

        def setter(raw_password):
            self.set_password(raw_password)
            # Password hash upgrades shouldn't be considered password changes.
            self._password = None
            User.objects.filter(pk=self.pk, password=checked_hash).update(
                password=self.password
            )

        return check_password(raw_password, checked_hash, setter)

    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between."""
        return " ".join(filter(None, (self.first_name, self.last_name)))

    def get_short_name(self):
        """Return the short name for the user."""
        return (self.first_name or "").strip()

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)


@receiver(post_delete, sender=User)
def delete_unused_location(sender, instance, **kwargs):
    """Delete a removed account's address unless another account still uses it.

    The foreign key points from the account to its address, so deleting the
    account never cascades to the address, and no other record refers to it.
    Deleting an address that is still in use would cascade to its accounts.
    """
    if instance.location_id is not None:
        Location.objects.filter(pk=instance.location_id, user__isnull=True).delete()


class TokenManager(models.Manager):
    """Manager for Token model."""

    def create_token(self, **kwargs):
        """Issue a token using the configured expiry unless explicitly supplied.

        The token string is on the ``key`` attribute of the returned instance
        and nowhere else: the database stores only its digest.
        """
        if "expires" not in kwargs:
            kwargs["expires"] = now() + accounts_settings.TOKEN_EXPIRES_SECONDS

        key = TOKEN_PREFIX + secrets.token_hex(32)
        token = self.create(digest=token_digest(key), **kwargs)
        token._key = key
        return token

    def expire_for_user(self, user: User) -> None:
        """Expire all tokens for the given user."""
        self.filter(user=user).update(expires=now())


class Token(models.Model):
    """Authorization token model."""

    # Set by ``create_token`` on the instance it returns. A token loaded from
    # the database keeps this default, because its string is not stored.
    _key: str | None = None

    digest = models.CharField(max_length=64)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="auth_tokens", on_delete=models.CASCADE
    )

    created = models.DateTimeField(auto_now_add=True)

    expires = models.DateTimeField()

    objects = TokenManager()

    class Meta:
        """Token's meta options."""

        constraints = [
            # A character column defaults to the empty string, which a row
            # created without a digest would otherwise store.
            models.CheckConstraint(
                condition=~models.Q(digest=""), name="accounts_token_digest_not_empty"
            ),
            # A constraint rather than ``unique=True``, which on PostgreSQL
            # also adds a ``varchar_pattern_ops`` index that no lookup uses:
            # tokens are only found by an equal digest.
            models.UniqueConstraint(
                fields=["digest"], name="accounts_token_digest_unique"
            ),
        ]

    @property
    def key(self) -> str:
        """Return the token string of a token that ``create_token`` issued.

        :raises ValueError: If the token was loaded from the database, which
            keeps only its digest. Not an ``AttributeError``, which DRF turns
            into an omitted field of a read-only serializer field.
        """
        if self._key is None:
            raise ValueError(
                "A stored token has no key because only its digest is kept."
            )
        return self._key

    @property
    def is_expired(self):
        """Return whether the token has reached its expiry."""
        return self.expires <= now()

    def expire(self) -> None:
        """Expire this token now, leaving the account's other tokens as they are."""
        self.expires = now()
        # An update changes nothing if the row is already gone, as after the
        # account was deleted, where saving would fail.
        type(self).objects.filter(pk=self.pk).update(expires=self.expires)

    def __str__(self):
        """Describe the token without revealing its key or digest."""
        return f"Token issued {self.created}"
