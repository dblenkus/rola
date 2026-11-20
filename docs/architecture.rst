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
   Accounts: registration, activation, token login, password recovery and the
   account emails. It also installs the admin site, whose
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
registers the contest admin with the contest download.

Each app has the same shape. ``models.py`` holds the models and a query set
whose methods name the rules about which rows qualify, such as the contests
in judging. ``services.py`` holds writes that enforce rules across models,
such as an upload's photograph limit and its idempotency key, and the rules
that the API checks before a change, such as whether a contest still accepts
entries. The ``api`` package holds the serializers, views, filters and
permissions, and ``routes.py``, which registers the app's endpoints on the
project's router. The ``accounts`` API package also holds the token
authentication and the rate limits.
The tests are in ``backend/tests``, one directory per app.

The API under ``/api/v1`` accepts one credential, the login token, in the
header ``Authorization: Bearer <token>``. A login answers with the token and
the time it expires, two days later. A logout,
``DELETE /api/v1/tokens/current``, expires the token that the request carries
at once and leaves the account's other tokens valid. The token is
``rola_st_`` followed by 64 hexadecimal digits. The ``accounts_token`` table
stores its SHA-256 digest instead of the token, so a token cannot be read from
the database or from a copy of it.

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

``design``
   Rola's design system: the design tokens in ``tokens.json`` and the
   ``tokens.css`` generated from them, the system's component styles in
   ``components.css``, the font faces, the app-wide rules in ``app.css``
   and the logos.
``app``
   The entry point, the routes, the Redux store, the application shell, the
   translations, the service worker's registration and the Sentry setup.
``shared``
   Code that knows no feature: the API client and types, the component kit,
   hooks and utilities.
``features``
   ``auth``, ``contests``, ``upload``, ``jury``, ``results``, ``admin`` and
   ``notifications``. Each holds its API calls in ``api.ts``, and its
   components, pages and Redux Toolkit slices.
``test``
   Fixtures, API mocks and the test setup.
``sw.ts``
   The service worker.

ESLint enforces the direction of the imports: ``shared`` imports nothing from
``app`` or a feature, and a feature imports another feature only through the
other feature's ``index.ts``. Features may import the store's types and
hooks from ``app``; no rule covers that direction. The API client therefore
does not import the store: the store registers the client's handler for
unexpected failures, which shows the error notification, when it is created.

The design system comes from outside the repository. ``components.css`` is
its published stylesheet, kept unchanged, and its classes start with
``rl-``. ``layers.css`` puts it and ``tokens.css`` in a ``design-system``
cascade layer, above a ``base`` layer for the element defaults in
``app.css``; the app's own rules are unlayered, so they override the design
system whatever their specificity and whatever order the production build
links the files in. The kit in ``shared/ui`` builds the components that pages use on
those classes, with React Aria Components supplying keyboard, touch and
screen-reader behaviour. A component's own CSS sits beside it, with classes
that start with ``ui-``; the shell's start with ``shell-``, the service
worker prompts' with ``pwa-``, and each feature's with the feature's name,
such as ``upload-``. The layout responds
to the viewport through CSS alone, with two breakpoints, phones below
40rem and wide screens from 64rem, so every width renders the same DOM.

The design system has a light and a dark theme, which differ only in the
values of the colour tokens. ``tokens.css`` declares the light values on
``:root`` and on any element with ``data-theme="light"``, and the dark
values on any element with ``data-theme="dark"`` and, when the device
prefers dark, on a root without the attribute. The page therefore follows
the device from CSS alone. A person's choice in the account menu, which is
called the appearance because a theme is part of a contest, is kept in the
browser's storage under ``rola.appearance`` and put on ``<html>`` as
``data-theme``, by ``/appearance.js`` before the first paint and by
``app/appearance`` afterwards; the script is a file of its own because the
script policy allows no inline script. The judge's scoring view is drawn
with the light values on its own dark surface, so its root carries
``data-theme="light"``, as do the notification, the update prompt, the
offline band and the skip link while that view is open. Organizer-written
HTML is stripped of its own colours and classes when it is sanitized, so
that it reads in both themes.

The shell in ``app`` picks a layout per route: the standard one with the
app bar, the main navigation and the footer; its task variant for the
upload form, which hides the bars on a phone; and a bare one for the judge's
scoring view, which takes the whole window. The main navigation is one
``nav``, in the app bar on wider screens and a tab bar fixed to the bottom
on phones. Every page is a lazily loaded chunk with its own Suspense
boundary, an error boundary around the routes shows a page that failed to
render with a reload button, and an unknown address shows "Page not found".
Each page has one ``h1`` and its own document title, and after a navigation
focus moves to the page's ``main``.

The service worker, built from ``src/sw.ts`` by ``vite-plugin-pwa``,
precaches the build output: scripts, styles, fonts, icons,
``site.webmanifest`` and ``index.html``. Navigations go to the network, and only when the network
cannot be reached does the worker answer them with the precached
``index.html``, because every document carries a script policy nonce of its
own (see :doc:`deployment`). Navigations to the paths that
``app/pwa/serverPaths.ts`` lists are left to the server. The worker caches
nothing at run time, so API responses, which belong to one account, and
photographs, whose S3 links expire, always come from the network. A new
version installs in the background and waits, because taking over deletes
the previous version's files, which open pages may still need: an entrant
may be uploading and a judge scoring. A page built with the new version,
loaded from the network after the release, lets it take over without a
prompt when it is the site's only open window; while other windows are
open, it asks again at its next update check. A page of the previous
version shows the update prompt, and the new version takes over when the
person presses Reload. Only production builds register the worker.

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
container. It serves ``/sw.js`` and ``/site.webmanifest`` uncached, so
browsers find a new release, and answers 404 instead of the application for
a missing file at the root or under ``/assets/``. Once a browser has the
service worker, the worker answers requests for its precached files itself,
passes navigations to the application's pages to nginx and answers them
itself only when nginx cannot be reached, and leaves every other request to
the network.
:doc:`deployment` describes what the TLS terminator
must do, and the Cloudflare Tunnel that ``compose.tunnel.yaml`` runs in the
terminator's place, with no port published on the host.
