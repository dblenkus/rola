"""Minimal host contracts; this is not a production authentication app."""

import uuid

from django.contrib.auth.models import AbstractUser
from django.core.mail import send_mail
from django.db import models


class Location(models.Model):
    """Expose the country used in contest results."""

    country = models.CharField(max_length=100)


class User(AbstractUser):
    """Exercise Rola's separate integer primary key and public UUID."""

    internal_id = models.AutoField(primary_key=True)
    id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    location = models.ForeignKey(
        Location, null=True, blank=True, on_delete=models.SET_NULL
    )


class Email(models.Model):
    """Implement the host-provided confirmation email contract."""

    subject = models.CharField(max_length=100)
    body = models.TextField()
    html_body = models.TextField(null=True, blank=True)

    def send(self, address):
        """Send a confirmation through the test mail backend."""
        send_mail(self.subject, self.body, None, [address], html_message=self.html_body)
