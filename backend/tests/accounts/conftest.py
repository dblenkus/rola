"""Provide an active account, its API client, an address and a login budget."""

from unittest.mock import patch

import pytest

from rola.accounts.api.throttling import LoginThrottle
from rola.accounts.models import User
from tests.factories import logged_in_client


@pytest.fixture
def account(db):
    """Create an active account with an independent login credential."""
    return User.objects.create_user(
        email="person@example.com", password="Original!73", is_active=True
    )


@pytest.fixture
def client(account):
    """Authenticate API calls as the fixture account."""
    return logged_in_client(account)


@pytest.fixture
def address():
    """Provide a complete postal address for account writes."""
    return {
        "address": "Street 1",
        "city": "Ljubljana",
        "postal_code": "1000",
        "country": "SI",
    }


@pytest.fixture
def budget():
    """Allow two login attempts per client address."""
    with patch.object(LoginThrottle, "rate", "2/hour", create=True):
        yield
