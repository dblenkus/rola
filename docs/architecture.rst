============
Architecture
============

Rola is a Django backend and a React frontend in one repository, so an API
change and the client code that uses it are reviewed together. Each side has
its own dependency manifest, lockfile and image.

Backend
=======

The backend in ``backend/`` is one Python distribution, ``rola``:

* ``rola`` is the Django project. It reads its configuration from the
  environment, routes the URLs, and installs the admin site whose login
  shares the API login's rate limit.
* ``drf_user`` holds the accounts: registration, activation, token login,
  password recovery and the profile.
* ``rolca`` holds the contest domain: ``core`` (contests, themes, authors,
  submissions and photographs), ``rating`` (juries, ratings, results and
  rewards) and ``payment``.
* ``utils`` provides the ``readinesscheck`` command that the container health
  check runs.

PostgreSQL holds all state. The ``rola_cache`` table, created by
``createcachetable``, keeps the rate-limit counters, so every Gunicorn worker
sees the same counts. Sessions, which only the Django admin uses, are stored
in the database too. Uploaded photographs live in the ``media`` volume or in
S3.

Frontend
========

The frontend in ``frontend/`` is a client-rendered React application built
with Vite. It calls the API under ``/api/v1`` on its own origin and
authenticates with a token that it keeps in the browser's local storage. The
backend therefore sends no CORS headers: in production nginx serves the
application and the API from one origin, and in development the Vite
development server forwards the backend paths to Django.

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
itself, and passes ``/api``, ``/core`` and ``/django-admin`` to Gunicorn in
the backend container. :doc:`deployment` describes what the TLS terminator
must do.
