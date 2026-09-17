import logging

from django.core.management.base import BaseCommand
from django.db import connections

logger = logging.getLogger(__name__)


def check_database():
    """Check connections to all databases."""
    try:
        for name in connections:
            cursor = connections[name].cursor()
            cursor.execute("SELECT 1;")
            row = cursor.fetchone()
            if row is None:
                raise RuntimeError("db: Invalid response.")
    except Exception as ex:
        logger.exception(ex)
        raise RuntimeError("db: Cannot connect to database.")


class Command(BaseCommand):
    """Readiness check for Django application."""

    help = "Readiness check for Django application."

    def handle(self, *args, **options):
        """Comand handle."""
        try:
            check_database()
        except RuntimeError as ex:
            raise SystemExit(ex)
