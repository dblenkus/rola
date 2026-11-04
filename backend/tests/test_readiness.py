"""Report the backend ready only when its database and cache answer queries."""

from unittest.mock import patch

import pytest
from django.core.management import CommandError, call_command
from django.db import connection, connections
from django.db.utils import OperationalError

pytestmark = pytest.mark.django_db


def test_readiness_passes_with_database_and_cache_table():
    call_command("readinesscheck")


def test_readiness_reports_why_the_database_is_unavailable():
    refused = OperationalError("connection refused")

    with (
        patch.object(connections["default"], "cursor", side_effect=refused),
        pytest.raises(
            CommandError, match="Database default is unavailable: connection refused"
        ),
    ):
        call_command("readinesscheck")


def test_readiness_fails_without_the_cache_table():
    with connection.cursor() as cursor:
        cursor.execute("DROP TABLE rola_cache")

    with pytest.raises(CommandError, match="createcachetable") as excinfo:
        call_command("readinesscheck")
    assert "rola_cache" in str(excinfo.value)
