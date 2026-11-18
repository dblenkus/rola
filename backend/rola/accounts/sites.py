"""Serve the Django admin under the API's login rate limit."""

import math

from django.contrib import admin
from django.contrib.auth.decorators import login_not_required
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache

from rola.accounts.api.throttling import LoginThrottle


class RolaAdminSite(admin.AdminSite):
    """Admin site whose login shares the API login throttle."""

    @method_decorator(never_cache)
    @login_not_required
    def login(self, request, extra_context=None):
        """Refuse login attempts once the client address exhausts its budget.

        Admin and API logins count against the same ``login`` throttle
        scope and client address, so neither can be used to bypass the
        other's limit. A refusal carries ``Retry-After``, as the API
        login's does.
        """
        throttle = LoginThrottle()
        if request.method == "POST" and not throttle.allow_request(request, None):
            response = HttpResponse(
                "Too many login attempts. Try again later.",
                content_type="text/plain; charset=utf-8",
                status=429,
            )
            wait = throttle.wait()
            if wait is not None:
                response["Retry-After"] = str(math.ceil(wait))
            return response
        return super().login(request, extra_context)
