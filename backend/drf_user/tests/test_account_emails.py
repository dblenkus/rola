"""Render account emails as plain text."""

import pytest
from django.core import mail
from django.test import override_settings

from drf_user.models import User
from drf_user.utils.signing import send_activation_email, send_reset_email


@override_settings(DRF_USER_APP_NAME="Foto & Video")
@pytest.mark.parametrize("send", [send_activation_email, send_reset_email])
def test_plain_text_emails_keep_names_unescaped(send):
    send(User(email="obrien@example.org", first_name="O'Brien & Co"))
    (message,) = mail.outbox
    assert "Foto & Video" in message.subject
    assert "Hello O'Brien & Co!" in message.body
    assert "&amp;" not in message.subject + message.body
    assert "&#x27;" not in message.body
