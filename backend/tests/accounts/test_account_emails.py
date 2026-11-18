"""Render account emails as plain text."""

from django.core import mail
from django.test import override_settings

from rola.accounts.models import User
from rola.accounts.utils.signing import (
    send_activation_email,
    send_existing_account_email,
    send_reset_email,
)


@override_settings(ACCOUNTS_APP_NAME="Foto & Video")
def test_plain_text_emails_keep_names_unescaped():
    send_reset_email(User(email="obrien@example.org", first_name="O'Brien & Co"))
    (message,) = mail.outbox
    assert "Foto & Video" in message.subject
    assert "Hello O'Brien & Co!" in message.body
    assert "&amp;" not in message.subject + message.body
    assert "&#x27;" not in message.body


def test_activation_email_leaves_out_the_registrant_name():
    send_activation_email(
        User(
            email="victim@example.org",
            first_name="Ana!\n\nYour photo won. Claim it at https://evil.example/claim",
        )
    )
    (message,) = mail.outbox
    assert message.to == ["victim@example.org"]
    assert message.body.startswith("Hello!\n")
    for text in ("Your photo won", "evil.example"):
        assert text not in message.subject + message.body


def test_existing_account_email_leaves_out_the_account_name():
    send_existing_account_email(
        User(
            email="victim@example.org",
            first_name="Ana!\n\nYour photo won. Claim it at https://evil.example/claim",
        )
    )
    (message,) = mail.outbox
    assert message.to == ["victim@example.org"]
    assert message.body.startswith("Hello!\n")
    for text in ("Your photo won", "evil.example"):
        assert text not in message.subject + message.body
