"""Store the payment state of submission sets."""

from django.db import models
from django.db.models import Q

from rola.common.models import BaseModel
from rola.entries.models import SubmissionSet


class Payment(BaseModel):
    """Model for storing payments."""

    submission_set = models.OneToOneField(SubmissionSet, on_delete=models.CASCADE)

    paid = models.BooleanField(default=False)


#: Selects the submissions that are in a paid submission set, as a filter on
#: ``Submission``. Judging and results show only these. The filter joins the
#: submission sets, so a submission in several paid sets matches once per set.
PAID_SUBMISSION = Q(submissionset__payment__paid=True)
