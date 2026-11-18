====
Rola
====

The backend of Rola, a platform for photography contests. The ``rola``
distribution holds one Django project: its configuration in
``rola.config``, shared code in ``rola.common``, and the apps
``rola.accounts``, ``rola.contests``, ``rola.entries``, ``rola.payments`` and
``rola.judging``.

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

The code that came with the Rolca contest, payment and rating apps is
licensed under Apache-2.0 (``licenses/Apache-2.0.txt``), the code that came
with the drf_user account app under BSD-3-Clause
(``licenses/BSD-3-Clause.txt``), and the rest under AGPL-3.0-only
(``LICENSE-AGPL``). ``licenses/README.rst`` names the modules that the
inherited code is in.
