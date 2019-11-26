import logging
import os

from django.core import signing
from django.urls import reverse
from django.template.loader import render_to_string
from rest_framework import exceptions

from drf_user.models import User
from drf_user.settings import drf_user_settings

logger = logging.getLogger(__name__)

USER_ACTIVATION_SALT = 'user_activation'
PASSWORD_RESET_SALT = 'password_reset'


def _generate_token(token_generator, user, salt):
    # Create a signed token, containing the user identifier and timestamp.
    return signing.dumps(obj=token_generator(user), salt=salt)


def generate_activation_token(user):
    def token_generator(user):
        return user.email

    return _generate_token(token_generator, user, USER_ACTIVATION_SALT)


def generate_reset_token(user):
    def token_generator(user):
        return {
            'email': user.email,
            'counter': user.password_reset_counter,
        }

    return _generate_token(token_generator, user, PASSWORD_RESET_SALT)


def _send_user_email(
    subject_template_name,
    email_template_name,
    token,
    user,
    url,
    html_email_template_name=None,
):
    """Send user-related e-mail with security token."""

    context = {
        'first_name': user.first_name,
        'app_name': drf_user_settings.APP_NAME,
        'url': '{}?token={}'.format(url, token),
    }

    subject = render_to_string(subject_template_name, context)
    subject = ''.join(subject.splitlines())
    body = render_to_string(email_template_name, context)
    html_body = render_to_string(html_email_template_name, context)

    email_kwargs = {}
    if html_body:
        email_kwargs['html_message'] = html_body

    try:
        user.email_user(subject, body, **email_kwargs)
    except Exception:
        logger.exception("Error while sending e-mail for user '{}'.".format(user.email))


def send_activation_email(user, request):
    """Send activation e-mail for a given user."""
    _send_user_email(
        subject_template_name=os.path.join(
            'drf_user', 'registration', 'email_subject.txt'
        ),
        email_template_name=os.path.join('drf_user', 'registration', 'email_body.txt'),
        token=generate_activation_token(user),
        user=user,
        url=request.build_absolute_uri(reverse('user-activate-account')),
        html_email_template_name=os.path.join(
            'drf_user', 'registration', 'email_body.html'
        ),
    )


def send_reset_email(user, request):
    """Send reset password e-mail."""
    _send_user_email(
        subject_template_name=os.path.join(
            'drf_user', 'password_reset', 'email_subject.txt'
        ),
        email_template_name=os.path.join(
            'drf_user', 'password_reset', 'email_body.txt'
        ),
        token=generate_reset_token(user),
        user=user,
        url=request.build_absolute_uri(reverse('user-password-reset')),
        html_email_template_name=os.path.join(
            'drf_user', 'password_reset', 'email_body.html'
        ),
    )


def validate_activation_token(token):
    """Validate activation token and return referenced user."""
    try:
        email = signing.loads(
            token,
            salt=USER_ACTIVATION_SALT,
            max_age=drf_user_settings.ACTIVATION_TOKEN_EXPIRES_SECONDS.total_seconds(),
        )
        user = User.objects.get(email=email, is_active=False)
    except (signing.BadSignature, User.DoesNotExist):
        raise exceptions.ValidationError('Bad token.')

    return user


def validate_reset_token(token):
    """Validate password reset token and return referenced user."""
    try:
        data = signing.loads(
            token,
            salt=PASSWORD_RESET_SALT,
            max_age=drf_user_settings.RESET_TOKEN_EXPIRES_SECONDS.total_seconds(),
        )
        user = User.objects.get(
            email=data['email'], password_reset_counter=data['counter'],
        )
    except (signing.BadSignature, User.DoesNotExist):
        raise exceptions.ValidationError('Bad token.')

    if not user.is_active:
        raise exceptions.ValidationError("Account is not activated, contact support.")

    return user
