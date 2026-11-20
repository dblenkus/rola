"""Change account passwords and revoke what the old password protected."""

from rola.accounts.models import Token, User


def change_password(user: User, new_password: str) -> None:
    """Set the account's password and revoke its login tokens and reset links.

    The caller runs it inside a transaction, on an account row that it has
    locked with ``select_for_update``, after it has validated the new
    password. Only the password and the reset counter are saved, so no other
    change to the instance is written.

    :param user: The locked account.
    :param new_password: The new password, in plain text.
    """
    user.set_password(new_password)
    # Reset links sign the counter, so a new value invalidates those sent.
    user.password_reset_counter += 1
    user.save(update_fields=["password", "password_reset_counter"])
    Token.objects.expire_for_user(user)
