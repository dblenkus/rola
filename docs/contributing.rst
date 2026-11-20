============
Contributing
============

This page covers the development stack, the checks that CI runs, and the
maintenance tasks with steps that are easy to get wrong: regenerating
migrations, regenerating the API contract and updating dependencies.

Development stack
=================

Docker with Compose runs the whole application. From the repository root:

.. code-block:: shell

   docker compose up --build --wait

The stack needs no ``.env``. It serves the site on http://localhost:8080
through the Vite development server, which forwards ``/api``,
``/django-admin``, ``/media`` and ``/static2`` to Django's development
server. ``backend/`` and ``frontend/`` are mounted into the containers, so
both servers reload on changes. PostgreSQL 18 listens on
``127.0.0.1:55432`` with user, password and database ``rola``. Before the
backend starts, a one-off ``migrate`` service runs ``migrate`` and
``createcachetable``.

Create an account for the Django admin at
http://localhost:8080/django-admin/:

.. code-block:: shell

   docker compose exec backend python manage.py createsuperuser

Account emails are printed to the backend log (``docker compose logs
backend``). Sentry reporting stays off unless ``.env`` sets
``VITE_SENTRY_DSN``. Put only this variable in a development ``.env``: the
``COMPOSE_FILE`` line of ``.env.example`` selects the production stack.

The images hold the installed dependencies. After ``backend/uv.lock``
changes, rebuild with ``docker compose up --build --wait``. After
``frontend/package-lock.json`` changes, also replace the frontend's
``node_modules`` volume, which otherwise keeps the old packages:

.. code-block:: shell

   docker compose up -d --build --renew-anon-volumes frontend

The replaced volume stays behind unused; ``docker volume prune`` removes it.
``docker compose down`` keeps the database and the uploaded media;
``docker compose down -v`` deletes them.

Native development
==================

The backend needs uv 0.13.9, which downloads the Python version it needs. If
another uv version is installed, run every ``uv`` command below as ``uvx
--from uv==0.13.9 uv``. From ``backend/``, against the database of the
development stack:

.. code-block:: shell

   uv sync --locked --all-groups
   docker compose -f ../compose.yaml up -d --wait db
   export ROLA_DEBUG=true ROLA_SECRET_KEY=development-only-secret-key
   export ROLA_FRONTEND_URL=http://localhost:5173
   export ROLA_POSTGRESQL_HOST=127.0.0.1 ROLA_POSTGRESQL_PORT=55432
   export ROLA_POSTGRESQL_PASSWORD=rola
   uv run python manage.py migrate
   uv run python manage.py createcachetable
   uv run python manage.py runserver

The frontend needs Node.js 26.13.0, the version in ``frontend/.node-version``.
From ``frontend/``:

.. code-block:: shell

   npm ci
   npm run dev

The Vite development server listens on http://localhost:5173 and forwards the
backend paths to ``http://localhost:8000``; set ``API_PROXY_TARGET`` for
another address.

Checks
======

CI runs the jobs in ``.github/workflows/build.yml`` on every pull request,
on every push to ``main`` and once a week, so that new advisories against
the locked dependencies show up without a push. The ``Makefile`` in the
repository root holds the commands, and each check step of the workflow runs
one of its targets; only the wheel check, the image builds and the Compose
checks are written in the workflow itself. Run the same targets locally,
from the repository root, before opening a pull request. With another uv
than 0.13.9, pass ``UV="uvx --from uv==0.13.9 uv"`` to every ``make``
command. The targets set ``ROLA_SECRET_KEY``,
``ROLA_FRONTEND_URL`` and the database variables of the development stack
unless the environment already does.

.. code-block:: shell

   make backend-sync frontend-install
   make check

``make check`` runs the tests on SQLite and PostgreSQL, the system and
migration checks, lint, formatting, types and the documentation build of the
backend, the frontend's lint, formatting, type checks, tests and build, and
the API contract regeneration. It starts the ``db`` service of the
development stack for the tests on PostgreSQL. The lockfile check, the
migration of a database, the dependency checks and the audits run only as
their own targets.

Backend tests, which CI runs on Python 3.14 and 3.15; ``uv sync --locked
--all-groups --python 3.15`` from ``backend/`` switches the environment.
Deprecation warnings fail the tests (``filterwarnings`` in
``pyproject.toml``):

.. code-block:: shell

   make backend-test
   make backend-test-postgresql

pytest uses ``rola.config.test_settings``, which runs on an in-memory SQLite
database unless ``ROLA_TEST_POSTGRESQL`` is set, as
``backend-test-postgresql`` does. The tests of concurrent token redemption
need PostgreSQL's row locks and are skipped on SQLite. The database user must
be allowed to create the test database.

System checks and migrations. ``backend-migrate`` migrates the database that
``ROLA_POSTGRESQL_NAME`` names, ``rola`` by default, creates the cache table
and runs ``readinesscheck``; CI runs it on an empty database:

.. code-block:: shell

   make backend-system-check
   make backend-migrations-check
   make backend-migrate

Quality checks: the lockfile, Ruff's lint rules and formatting on the backend
and ``docs/conf.py``, mypy, the documentation (see `Documentation`_) and the
audit of the locked runtime dependencies:

.. code-block:: shell

   make backend-lock-check
   make backend-lint
   make backend-format
   make backend-types
   make docs
   make backend-audit

The quality job also builds the wheel, installs it with the locked runtime
dependencies into a clean environment, and checks there that Django starts,
migrates, queries a model, finds the email templates and loads the Slovenian
translations.

Frontend checks:

.. code-block:: shell

   make frontend-lint
   make frontend-format
   make frontend-typecheck
   make frontend-test
   make frontend-build
   make frontend-deps
   make frontend-audit

``frontend-audit`` runs ``npm audit --omit=dev``. Without ``--omit=dev``,
``npm audit`` also reports a moderate minimatch advisory in the development
tooling, which has no fix yet.

The API contract job regenerates both generated files (see `API contract`_)
and fails if either differs from the committed one; ``make api-contract``
does the same. The image job builds the development and production targets
of both Dockerfiles, with a fake value for the frontend's build argument,
and pushes nothing. It starts the production frontend image and checks that
its page carries the ``Content-Security-Policy`` and loads scripts from the
site's own paths only. The Compose job runs ``docker compose config`` on
``compose.yaml``, on ``compose.production.yaml``, and on the production file
merged with ``compose.tunnel.yaml``, where it also checks what the merge
removes and overrides. The GitHub configuration job lints the workflows with
actionlint, in Docker, and validates ``.github/dependabot.yml`` against
Dependabot's schema:

.. code-block:: shell

   make actionlint
   make dependabot-config

actionlint 1.7.12 does not know the ``ubuntu-26.04`` runner label, so
``.github/actionlint.yaml`` declares it.

API contract
============

After changing a serializer, a view or a schema annotation, regenerate
``backend/openapi.yaml`` and ``frontend/src/shared/api/generated-api.ts``
from it, and commit both with the change:

.. code-block:: shell

   make api-schema api-types

The schema is generated with the production settings, which select the PostgreSQL
backend; no database server needs to run. drf-spectacular takes integer
bounds from the database backend, so generating with ``rola.config.test_settings``
(SQLite) would publish 64-bit bounds for 32-bit and 16-bit columns. Review
both diffs with the change, update the frontend code and tests that use the
changed responses, and list the contract change in ``docs/CHANGELOG.rst``.

Migrations
==========

Each app has a single migration, ``0001_schema``, and the production data is
transferred into a database created from these migrations
(:doc:`transfer`). Until that first production deployment, a model change
regenerates its app's ``0001_schema`` in the same commit instead of adding a
second migration. A database that applied the previous ``0001_schema`` does
not change when the file is regenerated, so recreate the development
database after such a change, for example with ``docker compose down -v``,
which deletes its volumes. Once a deployed database has applied
``0001_schema``, regenerating it would break that database: add ordinary
migrations from then on. An upgrade applies them with ``docker compose run --rm migrate`` while
the previous release still serves requests ("Upgrades" in
:doc:`deployment`), so each migration must work with both releases. Drop or
rename a column only in a release after the one that stopped using it, and
give a new ``NOT NULL`` column a database default (``db_default``).

Regenerate one app at a time, so that each app keeps a single migration file.
The apps' migrations depend on each other in the order of the apps:
``contests`` on ``accounts``, ``entries`` on ``contests``, ``payments`` on
``entries``, and ``judging`` on ``contests`` and ``entries``. From
``backend/``:

#. Delete the app's ``migrations/0001_schema.py``.
#. The migration loader fails while a migration that another app's migration
   depends on is missing. For ``accounts``, ``contests`` and ``entries``,
   write a scratch settings module that marks the apps after it as
   unmigrated, and do not commit it. For ``accounts``, create
   ``backend/regen_settings.py``:

   .. code-block:: python

      from rola.config.test_settings import *  # noqa: F403

      MIGRATION_MODULES = {
          "contests": None,
          "entries": None,
          "payments": None,
          "judging": None,
      }

   For ``contests``, leave ``contests`` out of ``MIGRATION_MODULES``, and for
   ``entries`` leave out ``contests`` and ``entries``. ``payments`` and
   ``judging`` need no scratch module; use ``rola.config.test_settings``.
#. Generate the migration under the same name, so the dependencies of the
   other apps stay valid:

   .. code-block:: shell

      uv run python manage.py makemigrations accounts --name schema --settings=regen_settings

#. After regenerating ``judging``, add back the ``CryptoExtension()``
   operation as the first operation, with its import from
   ``django.contrib.postgres.operations``. makemigrations does not generate
   it, and judging orders submissions by ``SHA1()``, which the pgcrypto
   extension provides. ``tests/project/test_migrations.py`` fails without
   it.
#. Delete the scratch module, then run ``make backend-migrations-check`` and
   ``make backend-test-postgresql``.

Dependencies
============

Python packages are declared with version ranges in ``backend/pyproject.toml``
and locked with hashes in ``backend/uv.lock``. Upgrade one package with ``uv
lock --upgrade-package <name>``. npm packages are declared in
``frontend/package.json`` and locked in ``frontend/package-lock.json``;
``npm install <package>@<version>`` updates both. Generate the npm lockfile
with the npm that ships with Node.js 26.13.0.

Release-age policy
------------------

The resolvers refuse releases younger than 7 days: ``exclude-newer = "7
days"`` in ``[tool.uv]`` and ``min-release-age=7`` in ``frontend/.npmrc``.
This applies to manual and Dependabot version updates, whose cooldown is
7 days too. Compromised releases are usually found and withdrawn within days.
``uv tool run`` (``uvx``) does not read ``[tool.uv]``, so the tool runs in
the ``Makefile`` pass ``--exclude-newer "7 days"`` themselves; the pinned tool version alone
leaves its dependencies unrestricted.

The policy also holds back security fixes younger than 7 days. When such a fix
cannot wait:

* npm: from ``frontend/``, run ``npm install <package>@<fixed version>
  --min-release-age-exclude=<package>``, with one more
  ``--min-release-age-exclude`` for each package released in lockstep with
  it. Only the named packages skip the window: a dependency of the fix that
  is younger than 7 days still fails to resolve, and has to be checked and
  named as well. The flags apply to that command only, and the lockfile then
  pins the versions.
* uv: add the package, and every package released in lockstep with it, to
  ``exclude-newer-package`` in ``backend/pyproject.toml``, then run ``uv lock
  --upgrade-package <package>``. For example, exempting ``psycopg`` alone
  keeps the old version, because its ``binary`` extra pins ``psycopg-binary``
  to the same version:

  .. code-block:: toml

     [tool.uv]
     exclude-newer = "7 days"
     exclude-newer-package = { psycopg = false, psycopg-binary = false }

  Keep the exemption in ``pyproject.toml``. Passed on the command line
  instead, the setting is recorded in ``uv.lock``, and every later ``uv lock
  --check`` and ``uv sync --locked`` fails. Once the release is 7 days old,
  delete the entries and run ``uv lock``; the lock keeps the version.

Dependabot security updates skip the cooldown. For uv they run the same
resolver, so a fix younger than 7 days fails to resolve until the exemption is
applied by hand. For npm, Dependabot runs npm with ``--min-release-age=0``,
which overrides ``frontend/.npmrc``, so the fix and any new package it pulls in
can be hours old. Check their release dates, for example with ``npm view
<package> time``, before merging.

Pinned tools
------------

Dependabot updates the lockfiles, the Dockerfile base images, the Compose
images and the actions. These pins move by hand:

* uv 0.13.9 is pinned in three places: the ``uv`` stage in
  ``backend/Dockerfile``, the ``version`` inputs of setup-uv in
  ``.github/workflows/build.yml``, and this page. Dependabot updates only the
  Dockerfile; update the other two in the same pull request. An older uv
  writes an older lockfile revision, and setup-uv without a version installs
  the newest uv, which may be inside the release-age window. The uv version
  also sets the Python patch releases that CI tests, because CI uses only
  uv's own Python builds: 3.14.10 and 3.15.2 with uv 0.13.9.
* Node.js 26.13.0 is in ``frontend/.node-version``, which CI reads, and in
  ``frontend/Dockerfile``, which Dependabot updates. Keep them equal, and
  update the version that ``frontend/README.md`` and this page name with
  them. Dependabot ignores Node.js majors and ``@types/node`` majors, which
  move together by hand.
* The backend image's base is Python 3.14. Dependabot updates its patch
  release but ignores Python minor versions until PyYAML publishes wheels for
  Python 3.15; CI already tests 3.15.
* ``compose.yaml`` and ``compose.production.yaml`` pin the same PostgreSQL 18
  image, and CI starts its database from ``compose.yaml``. Dependabot ignores PostgreSQL majors, which
  need a dump and restore.
* pip-audit 2.10.1, actionlint 1.7.12 and check-jsonschema 0.39.0 in the
  ``Makefile``, the ``ubuntu-26.04`` runner label in the workflow and
  ``.github/actionlint.yaml``.
* The base OS release in the image tags: ``-alpine3.24`` for Node.js,
  nginx-unprivileged and PostgreSQL, and ``-slim-trixie`` for Python.
  Dependabot compares a tag only with tags of the same suffix, so it proposes
  nothing once an image publishes its new releases only for a newer base,
  such as ``-alpine3.25``. Check the published tags after each Alpine
  release, about every six months, and move the suffix by hand.

Documentation
=============

Build the documentation into ``docs/_build/html`` with warnings as errors;
``DOCS_BUILD`` selects another directory:

.. code-block:: shell

   make docs

``docs/conf.py`` sets up Django with ``rola.config.test_settings`` for
autodoc. User
or operator visible changes go into ``docs/CHANGELOG.rst``.
