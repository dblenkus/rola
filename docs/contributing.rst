============
Contributing
============

Development setup
=================

Use Python 3.12, 3.13, or 3.14. Create an isolated environment and install the
package with its development extras::

    python -m venv .venv
    . .venv/bin/activate
    python -m pip install -e '.[test,docs,lint,package]'

Start the disposable PostgreSQL and Redis services::

    docker compose -f tests/docker-compose.yml up -d --wait
    export ROLCA_POSTGRESQL_PORT=55432
    export ROLCA_POSTGRESQL_PASSWORD=rolca
    export ROLCA_REDIS_URL=redis://127.0.0.1:56379/0

Run the suite, including the Redis worker integration test::

    python -m pytest -W error::DeprecationWarning --cov=rolca --cov-report=xml
    python tests/manage.py check
    python tests/manage.py makemigrations --check --dry-run
    python tests/manage.py migrate --noinput
    python -m tox -e linters,docs,packaging

``tox -e py312,py313,py314`` runs each supported Python version when its interpreter
is installed. ``ROLCA_POSTGRESQL_HOST``, ``ROLCA_POSTGRESQL_NAME``,
``ROLCA_POSTGRESQL_USER``, ``ROLCA_POSTGRESQL_PASSWORD``, and
``ROLCA_POSTGRESQL_PORT`` override the test database connection. The database user
needs permission to create a test database. Redis tests skip only when
``ROLCA_REDIS_URL`` is unset; CI sets it in every test job.

Stop the local services after testing::

    docker compose -f tests/docker-compose.yml down

The ``tests.userapp`` models are a minimal host fixture with the historical
``drf_user`` label. They exercise a user whose public UUID differs from its integer
primary key, optional user location, and the confirmation-email relationship.
They are excluded from the installed wheel and are not an authentication package.

Updating dependencies
=====================

Declare direct runtime, build, and development dependencies in
``pyproject.toml``. Update their version ranges there and install the package
with the appropriate extras. Let the installer resolve transitive dependencies.

Run the Python matrix, migration checks, worker test, documentation build,
linters, and package checks. Keep historical
migration identities stable. Existing data and media need an upgrade rehearsal
in the host application as described in :doc:`upgrading`.

Preparing a release
===================

Version numbers come from Git tags via setuptools-scm. Fetch tags and history
before building; do not edit ``rolca.__about__`` to bump a version. Update
``docs/CHANGELOG.rst`` and run the required checks before creating a release tag.

Build and validate distributions in a clean output directory::

    python -m build
    python -m twine check dist/*

Inspect the wheel and source archive for migrations and translations, and install
the wheel into a fresh environment for a smoke test. Tag-triggered CI publishes
to TestPyPI using the existing repository secret. Production PyPI publication and
host deployment are separate release operations.
