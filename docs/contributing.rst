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
through the Vite development server, which forwards ``/api``, ``/core``,
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
backend``). The PayPal buttons and Sentry reporting stay off unless ``.env``
sets ``VITE_PAYPAL_CLIENT_ID`` or ``VITE_SENTRY_DSN``. Put only these two in a
development ``.env``: the ``COMPOSE_FILE`` line of ``.env.example`` selects
the production stack.

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

The backend needs uv 0.13.6, which downloads the Python version it needs. If
another uv version is installed, run every ``uv`` command below as ``uvx
--from uv==0.13.6 uv``. From ``backend/``, against the database of the
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
the locked dependencies show up without a push. Run the same commands
locally before opening a pull request.

Backend tests, on Python 3.14 and 3.15, from ``backend/``. Deprecation
warnings fail the tests (``filterwarnings`` in ``pyproject.toml``):

.. code-block:: shell

   uv sync --locked --all-groups --python 3.14
   uv run pytest
   docker compose -f ../compose.yaml up -d --wait db
   ROLA_TEST_POSTGRESQL=true ROLA_POSTGRESQL_HOST=127.0.0.1 \
       ROLA_POSTGRESQL_PORT=55432 ROLA_POSTGRESQL_PASSWORD=rola uv run pytest

pytest uses ``rola.test_settings``, which runs on an in-memory SQLite
database unless ``ROLA_TEST_POSTGRESQL`` is set. The tests of concurrent
token redemption need PostgreSQL's row locks and are skipped on SQLite. The
database user must be allowed to create the test database.

System checks and migrations, with the variables from `Native development`_
set; CI runs the last three commands on an empty database:

.. code-block:: shell

   uv run python manage.py check
   uv run python manage.py makemigrations --check --dry-run
   uv run python manage.py migrate --noinput
   uv run python manage.py createcachetable
   uv run python manage.py readinesscheck

Quality checks, from ``backend/``:

.. code-block:: shell

   uv lock --check
   uv run ruff check .
   uv run ruff format --check .
   uv run ruff check --config pyproject.toml ../docs/conf.py
   uv run ruff format --check --config pyproject.toml ../docs/conf.py
   uv run mypy
   uv run sphinx-build -W --keep-going -b html ../docs ../docs/_build/html
   uv export --frozen --no-dev --no-hashes --no-emit-project -o /tmp/audit.txt
   uvx --exclude-newer "7 days" --from pip-audit==2.10.1 \
       pip-audit -r /tmp/audit.txt --no-deps --disable-pip

The quality job also builds the wheel, installs it with the locked runtime
dependencies into a clean environment, and checks there that Django starts,
migrates, queries a model, finds the email templates and loads the Slovenian
translations.

Frontend checks, from ``frontend/``:

.. code-block:: shell

   npm ci
   npm run lint
   npm run format:check
   npm run typecheck
   npm test
   npm run build
   npm ls --all
   npm audit --omit=dev

``npm audit`` without ``--omit=dev`` also reports a moderate minimatch
advisory in the development tooling, which has no fix yet.

The API contract job regenerates both generated files (see `API contract`_)
and fails if either differs from the committed one. The image job builds the
development and production targets of both Dockerfiles, with fake values for
the frontend's build arguments, and pushes nothing. The Compose job runs
``docker compose config`` on both Compose files. The GitHub configuration job
lints the workflows with actionlint and validates ``.github/dependabot.yml``
against Dependabot's schema. To run the same checks before pushing, run from
the repository root:

.. code-block:: shell

   docker run --rm -v "$PWD":/repo -w /repo rhysd/actionlint:1.7.12
   uvx --exclude-newer "7 days" --from check-jsonschema==0.39.0 check-jsonschema \
       --builtin-schema vendor.dependabot .github/dependabot.yml

actionlint 1.7.12 does not know the ``ubuntu-26.04`` runner label, so
``.github/actionlint.yaml`` declares it.

API contract
============

After changing a serializer, a view or a schema annotation, regenerate
``backend/openapi.yaml`` and the frontend types from it:

.. code-block:: shell

   cd backend
   ROLA_SECRET_KEY=schema-only ROLA_FRONTEND_URL=http://localhost:8080 \
       uv run python manage.py spectacular --file openapi.yaml --validate --fail-on-warn
   cd ../frontend
   npm run api:generate

The command uses the production settings, which select the PostgreSQL
backend; no database server needs to run. drf-spectacular takes integer
bounds from the database backend, so generating with ``rola.test_settings``
(SQLite) would publish 64-bit bounds for 32-bit and 16-bit columns. Review
both diffs with the change, update the frontend code and tests that use the
changed responses, and list the contract change in ``docs/CHANGELOG.rst``.

Migrations
==========

Each app has a single migration, ``0001_schema``, and the production data is
transferred into a database created from these migrations
(:doc:`transfer`). Until that first production deployment, a model change
regenerates its app's ``0001_schema`` in the same commit instead of adding a
second migration. Once a deployed database has applied ``0001_schema``,
regenerating it would break that database: add ordinary migrations from then
on. An upgrade applies them with ``docker compose run --rm migrate`` while
the previous release still serves requests ("Upgrades" in
:doc:`deployment`), so each migration must work with both releases. Drop or
rename a column only in a release after the one that stopped using it, and
give a new ``NOT NULL`` column a database default (``db_default``).

Regenerate one app at a time, so that each app keeps a single migration file.
From ``backend/``:

#. Delete the app's ``migrations/0001_schema.py``.
#. Other apps' migrations depend on ``drf_user`` and ``core``, and the
   migration loader fails while their dependency is missing. For those two
   apps, write a scratch settings module that marks the dependent apps as
   unmigrated, and do not commit it. For ``drf_user``, create
   ``backend/regen_settings.py``:

   .. code-block:: python

      from rola.test_settings import *  # noqa: F403

      MIGRATION_MODULES = {"core": None, "payment": None, "rating": None}

   For ``core``, leave ``core`` out of ``MIGRATION_MODULES``. ``payment``
   and ``rating`` need no scratch module; use ``rola.test_settings``.
#. Generate the migration under the same name, so the dependencies of the
   other apps stay valid:

   .. code-block:: shell

      uv run python manage.py makemigrations drf_user --name schema --settings=regen_settings

#. After regenerating ``rating``, add back the ``CryptoExtension()``
   operation as the first operation, with its import from
   ``django.contrib.postgres.operations``. makemigrations does not generate
   it, and judging orders submissions by ``SHA1()``, which the pgcrypto
   extension provides. ``tests/test_migrations.py`` fails without it.
#. Delete the scratch module, then run ``makemigrations --check --dry-run``
   and the tests on PostgreSQL.

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
``uvx`` does not read ``[tool.uv]``, so the tool runs on this page and in CI
pass ``--exclude-newer "7 days"`` themselves; the pinned tool version alone
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

``exclude-newer-package = { django = false }`` in ``backend/pyproject.toml``
is such an exemption, for the Django 6.1.3 security release, uploaded on
2026-11-03 at 15:21 UTC. After 2026-11-10 15:22 UTC, delete the line and run
``uv lock``; before then the lock fails, because no Django release inside the
window satisfies the ``>=6.1.3`` floor.

Pinned tools
------------

Dependabot updates the lockfiles, the Dockerfile base images, the Compose
images and the actions. These pins move by hand:

* uv 0.13.6 is pinned in three places: the ``uv`` stage in
  ``backend/Dockerfile``, the ``version`` inputs of setup-uv in
  ``.github/workflows/build.yml``, and this page. Dependabot updates only the
  Dockerfile; update the other two in the same pull request. An older uv
  writes an older lockfile revision, and setup-uv without a version installs
  the newest uv, which may be inside the release-age window. The uv version
  also sets the Python patch releases that CI tests, because CI uses only
  uv's own Python builds: 3.14.10 and 3.15.2 with uv 0.13.6.
* Node.js 26.13.0 is in ``frontend/.node-version``, which CI reads, and in
  ``frontend/Dockerfile``, which Dependabot updates. Keep them equal, and
  update the version that ``frontend/README.md`` and this page name with
  them. Dependabot ignores Node.js majors and ``@types/node`` majors, which
  move together by hand.
* The backend image's base is Python 3.14. Dependabot updates its patch
  release but ignores Python minor versions until PyYAML publishes wheels for
  Python 3.15; CI already tests 3.15.
* Both Compose files pin the same PostgreSQL 18 image, and CI starts its
  database from ``compose.yaml``. Dependabot ignores PostgreSQL majors, which
  need a dump and restore.
* pip-audit 2.10.1, actionlint 1.7.12 and check-jsonschema 0.39.0 in the
  workflow and on this page, and the ``ubuntu-26.04`` runner label.
* The base OS release in the image tags: ``-alpine3.24`` for Node.js,
  nginx-unprivileged and PostgreSQL, and ``-slim-trixie`` for Python.
  Dependabot compares a tag only with tags of the same suffix, so it proposes
  nothing once an image publishes its new releases only for a newer base,
  such as ``-alpine3.25``. Check the published tags after each Alpine
  release, about every six months, and move the suffix by hand.

Documentation
=============

Build the documentation from ``backend/`` with warnings as errors:

.. code-block:: shell

   uv run sphinx-build -W --keep-going -b html ../docs ../docs/_build/html

``docs/conf.py`` sets up Django with ``rola.test_settings`` for autodoc. User
or operator visible changes go into ``docs/CHANGELOG.rst``.
