"""Serve the Django admin under the API's login rate limit."""

import math

from django.contrib import admin
from django.contrib.auth.decorators import login_not_required
from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache

from rola.accounts.api.throttling import LoginThrottle
from rola.accounts.forms import RolaAdminPasswordChangeForm


def refuse_beyond_login_budget(
    request: HttpRequest, message: str
) -> HttpResponse | None:
    """Count a POST against the login budget and refuse it once that is used up.

    The admin's password checks and the API's count against the same
    ``login`` throttle scope and client address, so none can be used to
    bypass another's limit. A refusal carries ``Retry-After``, as the API's
    does. Other methods are neither counted nor refused.

    :param message: The plain text of the refusal.
    :return: The 429 response, or ``None`` if the request may proceed.
    """
    if request.method != "POST":
        return None
    throttle = LoginThrottle()
    # The throttle is typed for the REST framework's request and a view. It
    # reads only the request's META and headers, which Django's request has
    # too.
    if throttle.allow_request(request, None):  # type: ignore[arg-type]
        return None
    response = HttpResponse(
        message, content_type="text/plain; charset=utf-8", status=429
    )
    wait = throttle.wait()
    if wait is not None:
        response["Retry-After"] = str(math.ceil(wait))
    return response


class RolaAdminSite(admin.AdminSite):
    """Admin site whose login and password change share the API login throttle."""

    password_change_form = RolaAdminPasswordChangeForm

    @method_decorator(never_cache)
    @login_not_required
    def login(self, request, extra_context=None):
        """Refuse login attempts once the client address exhausts its budget."""
        refusal = refuse_beyond_login_budget(
            request, "Too many login attempts. Try again later."
        )
        if refusal is not None:
            return refusal
        return super().login(request, extra_context)

    def password_change(self, request, extra_context=None):
        """Refuse password changes once the client address exhausts its budget.

        The form checks the current password, which someone at an open admin
        session could otherwise guess without limit.
        """
        refusal = refuse_beyond_login_budget(
            request, "Too many password change attempts. Try again later."
        )
        if refusal is not None:
            return refusal
        return super().password_change(request, extra_context)
