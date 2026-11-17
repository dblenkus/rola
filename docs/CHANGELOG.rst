Unreleased
==========

The backend moves to Django 6.1 and Django REST framework 3.18, the frontend
to React 19, MUI 9, React Router 8 and Redux Toolkit, and the deployment to
current images. The existing data moves to the new stack through a one-off
transfer; see ``docs/transfer.rst``.

API changes
-----------

* ``reward_theme`` in the authors of theme results is an integer, the
  rewarded theme's id, instead of the same number as a string.
* The authors in theme and submission results have only ``id``,
  ``first_name``, ``last_name``, ``school``, ``club``, ``country``, ``reward``
  and ``reward_theme``; their date of birth, mentor, distinction, email and
  timestamps are no longer public. ``/api/v1/submission`` lists only the
  requester's own submissions, also after publication and for
  administrators, and another account's submission answers 404.
* ``/api/v1/judge/submission`` leaves out each submission's author. Judges
  used to get the author's name, date of birth, school, mentor, club and
  distinction, which the jury view does not show.
* Profile ``PUT`` works without a password. ``PUT`` and ``PATCH`` on
  ``/api/v1/user/{id}`` answer 400 when the request contains a password (use
  the change-password endpoint) or a different email address. A profile
  without an address returns its address fields as ``null`` instead of
  failing with 500.
* A password-reset request gets the same empty 200 response for unknown,
  inactive and active addresses; unknown addresses used to get 404. Malformed
  activation and reset tokens get 400.
* Login allows 30 attempts a minute per client address, shared with the
  Django admin login and with password changes, which check the current
  password. Registration and activation each allow 60 requests an hour per
  client address, and password-reset requests and confirmations share 30
  an hour. Requests beyond a limit get 429.
* Changing the password also invalidates the account's outstanding reset
  links, as resetting it already did. Both still expire its login tokens.
* Email addresses are stored in lowercase and matched without regard to case.
  Registering a case variant of an existing address answers 400 with "user
  with this email already exists.", the same message as for an exact
  duplicate; a domain-case variant used to fail with 500, and a local-part
  variant created a second account.
* Activation and reset emails link to the frontend under
  ``ROLA_FRONTEND_URL``; the backend placeholder pages that answered 501 are
  gone.
* The results of a published theme that has no results yet answer 404
  instead of 500.
* ``?submitted=`` on the contest list returns each contest once instead of
  once per submission.
* Paginated lists break ordering ties by primary key, so paging through a
  list sorted with ``?ordering=`` no longer repeats or skips rows.
* Validation errors for a batch submission, a list in the request body, are
  an object keyed by the index of each failing item instead of a list with an
  entry per item, as Django REST framework 3.18 reports them.
* Only the owner can change a submission, and only until its contest's
  results are published; after that, ``PUT`` and ``PATCH`` answer 403, as
  ``DELETE`` already did.
* ``PUT``, ``PATCH`` and ``DELETE`` on ``/api/v1/author/{id}`` answer 403
  once the author has submissions in a contest that no longer accepts
  entries because it has ended or its results are published, and so does
  ``DELETE`` on ``/api/v1/user/{id}`` once the account has.
  These requests used to succeed at any time, so an entrant could delete
  entries that the jury was rating or the results showed, with their
  ratings and rewards, or change the name shown in the results.
* A submission's author and photographs must belong to the requester, a
  photograph can belong to only one submission, and an update cannot change
  the author or the contest. Such requests answer 400.
* A submission request, single or batch, creates its submissions and their
  submission set in one transaction. An empty batch, a batch that mixes
  contests or authors, and a photograph used twice answer 400 and create
  nothing.
* Only a judge of the contest can create or change a rating, only until the
  results are published, and a rating cannot move to another submission.
* A judge has one rating per submission. Two saves of a judge's first rating
  at once used to store two ratings, which the results added up and which
  made every later change of that rating fail with 500; now the later save
  updates the rating.
* ``/core/contest/{id}/download`` answers 403 to anyone but the contest's
  organizer and superusers. Its archive holds every photograph of each
  submission, read through the configured storage.
* The API sends no CORS headers; the frontend calls it from the same origin.
* ``/api-auth/``, Django REST framework's session login, is removed. The API
  accepts only token authentication.
* The API answers JSON only. Django REST framework's browsable HTML pages,
  whose forms showed any account the titles of every submission, are gone:
  ``?format=api`` answers 404 and a request that accepts only ``text/html``
  answers 406.
* ``?current=`` on the account list is described as a presence flag: any
  non-empty value limits the list to the caller's own account.
* ``backend/openapi.yaml`` describes the API, generated with the PostgreSQL
  backend's integer bounds; the backend serves no schema at runtime.

Deployment changes
------------------

* ``compose.yaml`` runs the development stack and ``compose.production.yaml``
  the production stack; ``docker-compose.yml``, the frontend's own Compose
  file and ``deploy/`` are removed. The files name their Compose projects
  ``rola-development`` and ``rola-production``, so the production volumes
  are ``rola-production_db``, ``rola-production_media`` and
  ``rola-production_static``. ``.env.example`` sets
  ``COMPOSE_FILE=compose.production.yaml``, so on the server ``docker
  compose`` uses the production stack without ``-f``.
* Gunicorn serves the backend instead of Daphne. Redis, Channels, the backup
  worker and the backup feature are removed.
* The images run PostgreSQL 18.6 (from 12), Python 3.14.10, Node.js 26.13.0
  for the build, and nginx 1.30.6. Both application containers run as
  non-root users.
* nginx listens on port 8080, published on ``127.0.0.1`` only, and serves the
  frontend, media and static files itself; the separate proxy image is gone.
  It passes ``/api``, ``/core`` and ``/django-admin`` to Django, so the Django
  admin and the contest download are reachable from the internet; the proxy
  in ``deploy/nginx`` passed neither. The Django admin login shares the API
  login's rate limit.
* The database is no longer published on port 5432 of every interface, where
  the old stack accepted connections without a password. The production stack
  publishes no database port; reach the database with ``docker compose exec
  db psql``.
* The database starts from new migrations. A database with the old migration
  history is refused, and the data moves with the transfer procedure.
* A ``migrate`` service runs ``migrate``, ``createcachetable`` and
  ``collectstatic`` on every start, before the backend. The ``rola_cache``
  table is required, and the backend health check fails without it.
* New optional variables: ``ROLA_CSRF_TRUSTED_ORIGINS``, and
  ``ROLA_SMTP_HOST`` and ``ROLA_SMTP_PORT``, which default to the SES
  endpoint in eu-west-1 on port 465 that the previous deployment had built
  in. The backend image sets ``ROLA_MEDIA_ROOT`` and ``ROLA_STATIC_ROOT``.
* New required variables: ``ROLA_FRONTEND_URL``, ``ROLA_NUM_PROXIES``,
  ``VITE_PAYPAL_CLIENT_ID`` and ``VITE_SENTRY_DSN``, and
  ``ROLA_AWS_REGION_NAME`` when ``ROLA_USE_S3`` is on. The production stack
  also requires ``ROLA_SECRET_KEY``, ``ALLOWED_HOSTS`` and
  ``ROLA_POSTGRESQL_PASSWORD``.
* With ``ROLA_USE_S3``, ``ROLA_AWS_ACCESS_KEY_ID``,
  ``ROLA_AWS_SECRET_ACCESS_KEY`` and ``ROLA_AWS_S3_ENDPOINT_URL`` are
  optional.
* Removed variables: ``ROLA_REDIS_*``, ``ROLA_BACKUP_AWS_*``,
  ``ROLA_STATIC_URL`` and ``ROLA_MEDIA_URL`` (static files and photographs
  are served under ``/static2/`` and ``/media/``, or from the buckets with
  S3), and the frontend's ``REACT_APP_BASE_URL``.
* Boolean variables still take ``true``, ``false``, ``1``, ``0``, ``yes``,
  ``no``, ``on`` and ``off`` in any letter case, but an empty value, which
  meant false, and ``y``, ``t``, ``n`` and ``f`` now stop the backend; leave
  unused booleans unset.
* ``ROLA_DISABLE_PASSWORD_VALIDATORS`` is read as a boolean; any non-empty
  value, even ``false``, used to turn the password validators off.
* Outside debug mode, the backend redirects HTTP to HTTPS, sets secure
  cookies and sends HSTS for one year. It trusts ``X-Forwarded-Proto`` only
  with ``ROLA_TRUST_PROXY`` and ``X-Forwarded-Host`` only with
  ``ROLA_USE_X_FORWARDED_HOST``, and takes client addresses from
  ``X-Forwarded-For`` according to ``ROLA_NUM_PROXIES``.
* Outside debug mode and without SES, email is discarded instead of printed
  to the log.
* Sessions are stored in the database instead of Redis.
* Activation and password-reset links that the previous deployment sent no
  longer work, because Django now signs them with SHA-256 instead of SHA-1.
  An account that registered before the transfer and was not activated
  needs a new activation link; the transfer procedure shows how to send one
  on request.
* S3 media URLs are signed with SigV4 for ``ROLA_AWS_REGION_NAME``.
* nginx sends ``X-Frame-Options``, ``X-Content-Type-Options`` and
  ``Referrer-Policy``, hides its version, caches hashed assets for a year,
  and answers 404 for a missing asset instead of serving the application.
* nginx accepts uploads of up to 10 MiB; the previous proxy stopped at 1 MiB.
* The nginx and Gunicorn access logs leave out query strings and the
  ``Referer``, so activation and reset tokens are not logged.
* PostgreSQL logs an error without the failed statement and the error's
  detail, which hold the row's values, such as a participant's email
  address or password hash.
* Gunicorn runs ``WEB_CONCURRENCY`` workers, 2 by default, and ends a
  request after 120 seconds; Daphne had no time limit.
* The frontend reports errors to the Sentry DSN given at build time and sends
  no headers, cookies, request bodies or query strings with them.
* The contest download in the Django admin builds its archive in a
  temporary file instead of in memory, so the backend needs as much free
  disk as the archive instead of as much memory. nginx waits 120 seconds for
  it, the TLS terminator must wait as long, and nginx keeps up to 4 GiB of it
  on disk, so a slow browser does not hold a Gunicorn worker.
* CI no longer publishes images; they are built on the server.

Fixes
-----

* After an upload, opening another upload form in the same tab no longer
  jumps to the confirmation page.
* A failed upload releases the upload button and says that it failed, and an
  upload without photographs asks for one.
* An upload form in progress, with its photographs, survives a new login.
* Deleting a submission or a submission set also deletes its photographs
  and thumbnails from storage, and so does deleting a contest or a theme in
  the Django admin.
* The jury view ignores late rating responses for a photograph it has already
  left.
* The jury gallery and rater show a theme only once they have loaded it:
  nothing from the theme opened before, no rating during the load, and
  neither the result nor the error of a load the judge has left.
* Contest notices are sanitized: scripts, iframes, embedded objects,
  event-handler attributes and ``javascript:`` links are removed. Links that
  open in another window keep their ``target`` and get
  ``rel="noopener noreferrer"``.
* Photograph file names with quotes or non-ASCII letters upload correctly.
* Screen readers hear the upload form's photograph preview as "Selected
  photograph" or "No photograph selected" instead of "Missing", and the
  preview and the file input are named in the interface language.
* Activation and reset emails show names and the application name as
  written instead of with HTML escapes such as ``&amp;``.
* Theme results sort names in Slovenian alphabetical order and highlight an
  author's row only in the theme of the author's reward.
* The Django admin index no longer fails for an account without a first name.
* The Django admin's submission list and pages no longer fail when a
  submission has no title.
* The contest download sends a logged-out organizer to the Django admin
  login and back, instead of to a page that does not exist.

Development changes
-------------------

* The backend is one ``rola`` distribution declared in
  ``backend/pyproject.toml`` and locked in ``backend/uv.lock``. Ruff replaces
  black, flake8, isort and pydocstyle, and tox is gone.
* The frontend builds with Vite instead of Create React App, and npm with a
  lockfile replaces yarn.
* The backend requires Python 3.14 or later.
* Lockfile updates accept only releases at least 7 days old, except
  Dependabot's npm security updates.
* CI tests the backend on Python 3.14 and 3.15 against PostgreSQL 18.6,
  checks the frontend, the API contract, both images, both Compose files,
  the workflows and the Dependabot configuration, and runs weekly with the
  dependency audits. Dependabot proposes updates for
  every manifest.
* The wheel declares its licences as ``AGPL-3.0-only AND Apache-2.0 AND
  BSD-3-Clause``.
