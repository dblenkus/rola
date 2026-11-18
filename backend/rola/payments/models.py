""".. Ignore pydocstyle D400.

==============
Payment models
==============

.. autoclass:: rola.payments.models.Payment
    :members:

"""

from django.db import models

from rola.contests.models import BaseModel, SubmissionSet


class Payment(BaseModel):
    """Model for storing payments."""

    submissionset = models.OneToOneField(SubmissionSet, on_delete=models.CASCADE)

    paid = models.BooleanField(default=False)
