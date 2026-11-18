"""Keep the fresh migration graph apart from the historical migration chains."""

from io import StringIO

import pytest
from django.contrib.postgres.operations import CryptoExtension
from django.core.management import call_command
from django.db import connection
from django.db.migrations.exceptions import InconsistentMigrationHistory
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder

SCHEMA_APPS = ["accounts", "contests", "payments", "judging"]


@pytest.mark.django_db
def test_migrate_rejects_a_database_with_the_historical_chains():
    # The historical chains recorded 0001_initial for every app (core through
    # the replaces list of its squashed migration). Such a database must fail
    # before any DDL instead of looking fully migrated.
    recorder = MigrationRecorder(connection)
    recorder.migration_qs.filter(app__in=SCHEMA_APPS).delete()
    for app in SCHEMA_APPS:
        recorder.record_applied(app, "0001_initial")

    with pytest.raises(InconsistentMigrationHistory):
        call_command("migrate", plan=True, stdout=StringIO())


def test_rating_schema_installs_pgcrypto():
    # makemigrations does not generate CryptoExtension, so regenerating the
    # migration drops it, and judging (ordered by SHA1()) fails on PostgreSQL.
    migration = MigrationLoader(None).get_migration("judging", "0001_schema")

    assert any(isinstance(op, CryptoExtension) for op in migration.operations)
