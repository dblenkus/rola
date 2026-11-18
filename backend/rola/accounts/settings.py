"""Settings for the accounts app."""

from datetime import timedelta

from django.conf import settings


class AccountsSettings:
    """Provides settings as defaults."""

    @property
    def TOKEN_EXPIRES_SECONDS(self) -> timedelta:
        """Return the allowed lifespan of an authentication token."""
        seconds = getattr(settings, "ACCOUNTS_TOKEN_EXPIRES_SECONDS", 172_800)

        return timedelta(seconds=seconds)

    @property
    def RESET_TOKEN_EXPIRES_SECONDS(self) -> timedelta:
        """Return the allowed lifespan of a password reset token."""
        seconds = getattr(settings, "ACCOUNTS_RESET_TOKEN_EXPIRES_SECONDS", 86_400)

        return timedelta(seconds=seconds)

    @property
    def ACTIVATION_TOKEN_EXPIRES_SECONDS(self) -> timedelta:
        """Return the allowed lifespan of an account activation token."""
        seconds = getattr(
            settings, "ACCOUNTS_ACTIVATION_TOKEN_EXPIRES_SECONDS", 302_400
        )

        return timedelta(seconds=seconds)

    @property
    def APP_NAME(self) -> str:
        """Return name of the app."""
        return str(getattr(settings, "ACCOUNTS_APP_NAME", "Rola"))


accounts_settings = AccountsSettings()
