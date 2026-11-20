"""Authenticate expiring account tokens."""

from rest_framework import authentication, exceptions

from rola.accounts.models import TOKEN_PREFIX, Token, token_digest


class TokenAuthentication(authentication.TokenAuthentication):
    """Authenticate the login token of an ``Authorization: Bearer`` header."""

    keyword = "Bearer"
    model = Token

    def authenticate_credentials(self, key):
        """Reject unknown, expired and inactive-account credentials."""
        # Only a string with the prefix can be a login token, so anything else
        # is refused before it costs a query.
        if not key.startswith(TOKEN_PREFIX):
            raise exceptions.AuthenticationFailed("Invalid token")
        try:
            token = Token.objects.select_related("user").get(digest=token_digest(key))
        except Token.DoesNotExist as error:
            raise exceptions.AuthenticationFailed("Invalid token") from error
        if not token.user.is_active:
            raise exceptions.AuthenticationFailed("User inactive or deleted")
        if token.is_expired:
            raise exceptions.AuthenticationFailed("Token has expired")
        return token.user, token
