"""Abstract models shared by the apps."""

from django.conf import settings
from django.db import models


class BaseModel(models.Model):
    """Base model for all other models."""

    class Meta:
        """BaseModel Meta options."""

        abstract = True

    #: user who created the object
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE
    )

    #: date when the object was created
    created = models.DateTimeField(auto_now_add=True)

    #: date when the object was last modified
    modified = models.DateTimeField(auto_now=True)
