import logging

from rest_framework import authentication, exceptions

from .models import Token

logger = logging.getLogger(__name__)


class TokenAuthentication(authentication.TokenAuthentication):
    """Token based authentication."""

    model = Token

    def authenticate_credentials(self, key):
        """Attempt token authentication using the provided key."""
        try:
            token = self.model.objects.select_related('user').get(key=key)
        except self.model.DoesNotExist:
            message = 'Invalid token'
            logger.debug('Authentication failed: %s', message)
            raise exceptions.AuthenticationFailed(message)

        if not token.user.is_active:
            message = 'User inactive or deleted'
            logger.debug(
                'Authentication failed: %s', message, extra={'user': token.user}
            )
            raise exceptions.AuthenticationFailed(message)

        if token.is_expired:
            message = 'Token has expired'
            logger.debug(
                'Authentication failed: %s', message, extra={'user': token.user}
            )
            raise exceptions.AuthenticationFailed(message)

        return (token.user, token)
