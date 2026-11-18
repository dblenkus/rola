"""Verify mail failures remain diagnosable without exposing addresses."""

import logging
from smtplib import SMTPRecipientsRefused

import pytest

from rola.accounts.models import Email, User
from rola.accounts.utils.signing import send_reset_email


@pytest.mark.parametrize("kind", ["account", "contest"])
def test_mail_failure_logs_exception_type_without_recipient(monkeypatch, caplog, kind):
    recipient = "private@example.com"

    def fail(*args, **kwargs):
        raise SMTPRecipientsRefused({recipient: (550, b"Rejected private@example.com")})

    monkeypatch.setattr("rola.accounts.models.send_mail", fail)
    with caplog.at_level(logging.ERROR):
        if kind == "account":
            send_reset_email(User(email=recipient))
        else:
            Email(subject="Test", body="Test").send(recipient)
    assert "SMTPRecipientsRefused" in caplog.text
    assert recipient not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
