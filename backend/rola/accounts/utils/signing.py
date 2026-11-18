"""Create and validate signed account email tokens."""

import logging
from urllib.parse import urlencode

from django.conf import settings
from django.core import signing
from django.template.loader import render_to_string
from rest_framework import exceptions

from rola.accounts.models import User
from rola.accounts.settings import accounts_settings

logger = logging.getLogger(__name__)

USER_ACTIVATION_SALT = "user_activation"
PASSWORD_RESET_SALT = "password_reset"


def generate_activation_token(user: User) -> str:
    """Sign the address of an account awaiting activation."""
    return signing.dumps(user.email, salt=USER_ACTIVATION_SALT)


def generate_reset_token(user: User) -> str:
    """Sign the account address and current recovery generation."""
    return signing.dumps(
        {"email": user.email, "counter": user.password_reset_counter},
        salt=PASSWORD_RESET_SALT,
    )


def _send_user_email(
    user: User, template: str, path: str, token: str, **context: str
) -> None:
    """Email the user a frontend link that carries a signed token.

    :param context: Template variables besides ``app_name`` and ``url``.
    """
    base_url = settings.ROLA_FRONTEND_URL.rstrip("/")
    context |= {
        "app_name": accounts_settings.APP_NAME,
        "url": f"{base_url}{path}?{urlencode({'token': token})}",
    }
    subject = "".join(
        render_to_string(f"accounts/{template}/email_subject.txt", context).splitlines()
    )
    body = render_to_string(f"accounts/{template}/email_body.txt", context)
    html_body = render_to_string(f"accounts/{template}/email_body.html", context)
    try:
        user.email_user(subject, body, html_message=html_body)
    except Exception as error:
        logger.error("Unable to send account email (%s).", type(error).__name__)


def send_activation_email(user):
    """Send an activation link pointing to the configured frontend."""
    # Anyone can register any address, so the name is the registrant's text,
    # not the recipient's, and stays out of the mail.
    _send_user_email(
        user, "registration", "/register/activate", generate_activation_token(user)
    )


def send_reset_email(user):
    """Send a recovery link pointing to the configured frontend."""
    _send_user_email(
        user,
        "password_reset",
        "/password-reset",
        generate_reset_token(user),
        first_name=user.first_name or "",
    )


def send_existing_account_email(user):
    """Send a recovery link to an account whose address registered again."""
    # An inactive account's name is the text of whoever registered the
    # address first, so it stays out of the mail.
    _send_user_email(
        user, "existing_account", "/password-reset", generate_reset_token(user)
    )


def validate_activation_token(token: str, *, lock: bool = False) -> User:
    """Return the account referenced by a valid activation token.

    The account may already be active: a link opened again, or retried after
    a lost response, still refers to it.
    """
    try:
        email = signing.loads(
            token,
            salt=USER_ACTIVATION_SALT,
            max_age=accounts_settings.ACTIVATION_TOKEN_EXPIRES_SECONDS.total_seconds(),
        )
        if not isinstance(email, str):
            raise ValueError("Invalid token payload.")
        users = User.objects.select_for_update() if lock else User.objects
        return users.get(email__iexact=User.objects.normalize_email(email))
    except (signing.BadSignature, User.DoesNotExist, ValueError) as error:
        raise exceptions.ValidationError("Bad token.") from error


def validate_reset_token(token: str, *, lock: bool = False) -> User:
    """Return the account if the recovery generation still matches.

    The account may be inactive: registering its address again sends it a
    recovery link, and the reset activates it.
    """
    try:
        data = signing.loads(
            token,
            salt=PASSWORD_RESET_SALT,
            max_age=accounts_settings.RESET_TOKEN_EXPIRES_SECONDS.total_seconds(),
        )
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("email"), str)
            or type(data.get("counter")) is not int
        ):
            raise ValueError("Invalid token payload.")
        users = User.objects.select_for_update() if lock else User.objects
        return users.get(
            email__iexact=User.objects.normalize_email(data["email"]),
            password_reset_counter=data["counter"],
        )
    except (signing.BadSignature, User.DoesNotExist, ValueError) as error:
        raise exceptions.ValidationError("Bad token.") from error
