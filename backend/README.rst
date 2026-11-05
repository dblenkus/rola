====
Rola
====

The backend of Rola, a platform for photography contests. The ``rola``
distribution holds the Django project ``rola``, the account app
``drf_user``, the contest, judging and payment apps under ``rolca``, and
``utils`` with the ``readinesscheck`` command.

Development
===========

The backend needs Python 3.14 or later and the uv version that the
repository's ``docs/contributing.rst`` names; uv downloads the Python version
it needs. From this directory:

.. code-block:: shell

   uv sync --locked --all-groups
   uv run pytest
   uv run ruff check .
   uv run ruff format --check .
   uv run mypy

pytest runs on an in-memory SQLite database unless ``ROLA_TEST_POSTGRESQL``
is set. The repository's ``docs/contributing.rst`` describes the tests on
PostgreSQL, the remaining checks, migrations, the API contract and dependency
updates; ``docs/deployment.rst`` describes the production stack.

Licences
========

The apps under ``rolca`` are licensed under Apache-2.0 (``LICENSE``),
``drf_user`` under BSD-3-Clause (``drf_user/LICENSE``), and the rest under
AGPL-3.0-only (``LICENSE-AGPL``).
