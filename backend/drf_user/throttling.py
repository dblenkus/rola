"""Apply request limits to credential and email endpoints."""

from django.db import connection, transaction
from rest_framework.request import Request
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView


class ClientAddressThrottle(SimpleRateThrottle):
    """Limit requests by client address, even when the caller is authenticated."""

    def allow_request(self, request: Request, view: APIView) -> bool:
        """Check and record the request while no other worker checks its key.

        DRF reads the request history and writes it back in separate cache
        calls, so concurrent checks of one key would each pass on the same
        history. On PostgreSQL an advisory lock on the key serializes them.
        The database cache uses this connection, so the lock is held until
        the new history is committed.
        """
        key = self.get_cache_key(request, view)
        with transaction.atomic():
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", [key])
            return super().allow_request(request, view)

    def get_cache_key(self, request: Request, view: APIView) -> str:
        """Key the request count on the client address and the throttle scope."""
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class LoginThrottle(ClientAddressThrottle):
    """Limit login attempts."""

    scope = "login"


class RegistrationThrottle(ClientAddressThrottle):
    """Limit account registration."""

    scope = "registration"


class ActivationThrottle(ClientAddressThrottle):
    """Limit account activation."""

    scope = "activation"


class RecoveryThrottle(ClientAddressThrottle):
    """Limit password reset requests and confirmations."""

    scope = "recovery"
