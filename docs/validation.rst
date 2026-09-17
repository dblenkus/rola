==================
Upgrade validation
==================

The upgrade was validated on 17 September 2026, starting from Rolca commit
``d9876e37d8057009c10ef0c4d23a2b04d322f4eb``. The final supported framework is
Django 6.1.1 with DRF 3.18.1, django-filter 26.1, Pillow 12.3.0,
Channels 4.3.2, channels-redis 4.3.0, boto3 1.43.96, and psycopg 3.3.5.
Dependency declarations are maintained in ``pyproject.toml``.

Local checks
============

The following checks ran locally on macOS with isolated PostgreSQL 18.6 and
Redis 8.10.1 services. Deprecation warnings were treated as errors in the final
test matrix.

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Check
     - Result
   * - Python 3.12.13
     - 53 tests passed
   * - Python 3.13.15
     - 53 tests passed
   * - Python 3.14.7
     - 53 tests passed
   * - Django system checks
     - No issues
   * - Model migration comparison
     - No changes detected
   * - Fresh database migration
     - Complete migration graph applied successfully
   * - Lint and formatting
     - Ruff, Flake8, isort, and Black passed
   * - Documentation
     - Sphinx build passed with warnings treated as errors
   * - Packaging
     - Manifest, wheel, source archive, and Twine checks passed
   * - Clean wheel installation on Python 3.14.7
     - Django setup, dependency consistency, and all 53 tests passed

Regression coverage includes submission ownership, single and batch creation,
transaction rollback, author and file validation, filters, exports, payments,
judging order, rating updates, published results, image processing, and backup
retry behavior. The worker test uses a real Redis queue and the configured ASGI
consumer, with a fake S3 client. The thumbnail migration test uses historical
model state and a real stored image.

Earlier checkpoints passed on Django 4.2, 5.2, and 6.0 during the migration.
Those checkpoints are not additional supported targets of the final package.
GitHub Actions now defines the three-version matrix; hosted CI has not been run
as part of this local validation.

Deployment checks still required
================================

The test host provides a minimal ``drf_user`` fixture. The real Rola host,
its authentication dependencies, frontend, database, media, and AWS account
were not upgraded or deployed. Before release, complete the settings changes,
restored-data migration rehearsal, frontend checks, real backup/restore, and
rollback rehearsal described in :doc:`upgrading`.
