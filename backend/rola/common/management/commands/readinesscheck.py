"""Check that the configured databases and the cache table accept queries."""

from typing import Any

from django.core.cache import cache
from django.core.management.base import BaseCommand, CommandError
from django.db import connections
from django.db.utils import DatabaseError


def check_database() -> None:
    """Query every configured database and close its cursor."""
    for name in connections:
        try:
            with connections[name].cursor() as cursor:
                cursor.execute("SELECT 1")
                if cursor.fetchone() != (1,):
                    raise CommandError(f"Database {name} returned an invalid response.")
        except DatabaseError as error:
            raise CommandError(f"Database {name} is unavailable: {error}") from error


def check_cache() -> None:
    """Read from the database cache, which needs its own table."""
    try:
        cache.get("readinesscheck")
    except DatabaseError as error:
        raise CommandError(
            "The cache table is unavailable (if it is missing, run createcachetable "
            f"after migrate): {error}"
        ) from error


class Command(BaseCommand):
    """Run the database and cache readiness checks."""

    help = "Check database and cache readiness."

    def handle(self, *args: Any, **options: Any) -> None:
        """Fail when a database or the cache table cannot answer a query."""
        check_database()
        check_cache()
