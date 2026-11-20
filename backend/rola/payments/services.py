"""Record the payment state of submission sets."""

from rola.accounts.models import User
from rola.entries.models import SubmissionSet
from rola.payments.models import Payment


def set_payment(
    submission_set: SubmissionSet, paid: bool, user: User
) -> tuple[Payment, bool]:
    """Set whether the submission set is paid, creating its payment if it has none.

    A created payment records ``user`` as the account that created it; an
    update keeps the account that created the payment. Of two concurrent
    first calls for one set, the later one waits for the earlier one's
    payment and updates it.

    :param submission_set: The submission set that the payment is for.
    :param paid: Whether the set is paid.
    :param user: The superuser who sets the payment.
    :return: The payment, and whether it was created.
    """
    # update_or_create locks the payment row in its own transaction and,
    # when a concurrent insert wins the unique constraint, reads that row.
    return Payment.objects.update_or_create(
        submission_set=submission_set,
        defaults={"paid": paid},
        create_defaults={"paid": paid, "user": user},
    )
