"""Forms of the admin site."""

from django.contrib.admin.forms import AdminPasswordChangeForm
from django.core.exceptions import PermissionDenied
from django.db import transaction

from rola.accounts.models import User
from rola.accounts.services import change_password


class RolaAdminPasswordChangeForm(AdminPasswordChangeForm):
    """Change the logged-in staff account's password as the API does."""

    def save(self, commit: bool = True) -> User:
        """Replace the password and revoke outstanding login and reset tokens.

        :param commit: Must be true: the change is always saved, because the
            revocations cannot be left for the caller to save.
        :return: The account as saved, which replaces ``user`` on the form.
        :raises ValueError: If ``commit`` is false.
        :raises PermissionDenied: If the old password no longer matches.
        """
        if not commit:
            raise ValueError("A password change cannot be left unsaved.")
        with transaction.atomic():
            user = User.objects.select_for_update().get(pk=self.user.pk)
            # Validation checked the old password before the lock, so a
            # change or reset that committed since then must not be undone.
            # The hash also changes when a login upgrades it, so check the
            # password again against the hash the row holds.
            if user.password != self.user.password and not user.check_password(
                self.cleaned_data["old_password"]
            ):
                raise PermissionDenied("The old password is no longer valid.")
            change_password(user, self.cleaned_data["new_password1"])
        # Django's view derives the session's new hash from the form's user,
        # so an instance with the old hash would log the administrator out.
        self.user = user
        return user
