============
Architecture
============

Rola is a Django backend and a React frontend in one repository, so an API
change and the client code that uses it are reviewed together. Each side has
its own dependency manifest, lockfile and image.

Backend
=======

The backend in ``backend/`` is one Python distribution, ``rola``. The package
holds the project configuration and one Django app per domain:

``rola.config``
   The settings, which read the configuration from the environment, the URL
   configuration and the WSGI application. It is not an app.
``rola.common``
   The base model and serializer, the shared permissions, ordering filter and
   pagination, and the ``readinesscheck`` command that the container health
   check runs.
``rola.accounts``
   Accounts: registration, activation, token login, password recovery, the
   profile and the account emails. It also installs the admin site, whose
   login and password change share the API login's rate limit.
``rola.contests``
   What an organizer sets up: contests, themes and institutions.
``rola.entries``
   What an entrant submits: authors, submission sets, submissions and their
   photographs, with the upload rules, the photograph processing and the
   contest download.
``rola.payments``
   Payments, and the filter for paid submissions that judging and the results
   use.
``rola.judging``
   Juries, ratings, theme results and rewards.

The apps depend on each other in one direction. Each imports only from the
apps before it in the order ``common``, ``accounts``, ``contests``,
``entries``, ``payments``, ``judging``, and ``config`` composes them. Where an
earlier app needs a rule of a later one, the later app adds it: ``entries``
registers the contest admin with the contest download, and refuses to delete
an account through the API while the account has entries in a closed
contest.

Each app has the same shape. ``models.py`` holds the models and a query set
whose methods name the rules about which rows qualify, such as the contests
in judging. ``services.py`` holds writes that enforce rules across models,
such as an upload's photograph limit and its idempotency key, and the rules
that the API checks before a change, such as whether a contest still accepts
entries. The ``api`` package holds the serializers, views, filters and
permissions, and ``routes.py``, which registers the app's endpoints on the
project's router. The ``accounts`` API package also holds the token
authentication and the rate limits, and its ``routes.py`` takes the account
viewset that ``entries`` extends and lists the login and logout paths, which
the project routes before the router's paths.
The tests are in ``backend/tests``, one directory per app.

The API under ``/api/v1`` accepts one credential, the login token, in the
header ``Authorization: Bearer <token>``. A login answers with the token and
the time it expires, two days later. A logout, ``POST /api/v1/user/logout``,
expires the token that the request carries at once and leaves the account's
other tokens valid. The token is ``rola_st_`` followed by 64 hexadecimal
digits. The ``accounts_token`` table stores its SHA-256 digest instead of the
token, so a token cannot be read from the database or from a copy of it.

PostgreSQL holds all state. The ``rola_cache`` table, created by
``createcachetable``, keeps the rate-limit counters, so every Gunicorn worker
sees the same counts. Sessions, which only the Django admin uses, are stored
in the database too. Uploaded photographs live in the ``media`` volume or in
S3.

Frontend
========

The frontend in ``frontend/`` is a client-rendered React application built
with Vite. It calls the API under ``/api/v1`` on its own origin and
authenticates with the login token, which it keeps in the browser's local
storage and sends as ``Authorization: Bearer <token>``. The backend therefore
sends no CORS headers: in production nginx serves the application and the API
from one origin, and in development the Vite development server forwards the
backend paths to Django. Logging out expires the token on the server; a
session that ends in another way, such as by expiry, sends no request.

``frontend/src`` is organized by feature:

``app``
   The entry point, the routes, the Redux store, the page layout, the
   translations and the Sentry setup.
``shared``
   Code that knows no feature: the API client and types, user interface
   components, hooks and utilities.
``features``
   ``auth``, ``contests``, ``upload``, ``jury``, ``results``, ``admin`` and
   ``notifications``. Each holds its API calls in ``api.ts``, and its
   components, pages and Redux Toolkit slices.
``test``
   Fixtures, API mocks and the test setup.

ESLint enforces the direction of the imports: ``shared`` imports nothing from
``app`` or a feature, and a feature imports another feature only through the
other feature's ``index.ts``. Features may import the store's types and
hooks from ``app``; no rule covers that direction. The API client therefore does not import the
store: the store registers the client's handler for unexpected failures,
which shows the error notification, when it is created.

The API contract
================

``backend/openapi.yaml`` is generated from the backend by drf-spectacular,
and ``frontend/src/shared/api/generated-api.ts`` is generated from it by
openapi-typescript. Both files are committed, and CI regenerates them and
fails on any difference, so a serializer change cannot reach the frontend
unnoticed. The schema is generated with the PostgreSQL backend, because it
takes integer bounds from the database backend. The backend serves no schema
or API browser at runtime.

Requests in production
======================

A TLS terminator on the host forwards requests to the frontend container's
nginx on ``127.0.0.1:8080``. nginx serves the built application, its hashed
``/assets/``, uploaded ``/media/`` and the collected ``/static2/`` files
itself, and passes ``/api`` and ``/django-admin`` to Gunicorn in the backend
container. :doc:`deployment` describes what the TLS terminator
must do, and the Cloudflare Tunnel that ``compose.tunnel.yaml`` runs in the
terminator's place, with no port published on the host.
