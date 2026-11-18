==========
Deployment
==========

``compose.production.yaml`` runs Rola on one server behind a TLS terminator.
This page describes the services, their configuration, what the TLS
terminator must do, and how to start, upgrade and maintain the stack. The
one-off move of the data from the previous deployment is in :doc:`transfer`.

Run every command on this page from the repository root. The server's
``.env`` sets ``COMPOSE_FILE=compose.production.yaml`` (see `Configuration`_),
so every ``docker compose`` command run there uses the production stack.

The production file names its Compose project ``rola-production``, so its
volumes are ``rola-production_db``, ``rola-production_media`` and
``rola-production_static``. ``compose.yaml`` names the development project
``rola-development``: a command that uses it, for example one run from a
subdirectory of the checkout, acts on that separate project, and neither
replaces the production containers nor deletes their volumes.

Services
========

``db``
   PostgreSQL 18, with its data in the ``db`` volume.

``migrate``
   A one-off service that runs ``migrate --noinput``, ``createcachetable``
   and ``collectstatic --noinput``, then exits. It is the release command:
   an upgrade runs it with ``docker compose run --rm migrate`` while the
   previous backend still serves requests (see `Upgrades`_). Every ``docker
   compose up`` runs it again, and the backend starts only after it
   succeeds.

``backend``
   Gunicorn serving Django as uid 1000, with ``WEB_CONCURRENCY`` synchronous
   workers, 2 by default. Its health check runs ``readinesscheck``, which
   fails while the database or the ``rola_cache`` table is unavailable. It
   publishes no port.

``frontend``
   nginx as uid 101, published on ``127.0.0.1:8080``. It serves the
   built frontend, ``/media/`` from the ``media`` volume and ``/static2/``
   from the ``static`` volume, and passes ``/api`` and ``/django-admin`` to
   the backend. It looks up the backend's address again every 10 seconds, so
   it keeps working when the backend container is recreated. It waits up to 120 seconds for the backend's response and
   keeps up to 4 GiB of a response in a temporary file in its container;
   see `Contest downloads`_.

The images are built on the server from the checked-out revision; no image is
published to a registry.

Configuration
=============

Copy ``.env.example`` to ``.env``, fill it in, and keep it out of Git. Keep
its ``COMPOSE_FILE`` line, which selects the production Compose file.
Compose refuses to start while a value it requires is missing, and the
settings refuse to load while one they require is missing. The Compose file
itself sets ``ROLA_DEBUG=false``, ``ROLA_TRUST_PROXY=true`` and
``ROLA_POSTGRESQL_HOST=db``. Booleans take ``true``, ``false``, ``1``,
``0``, ``yes``, ``no``, ``on`` or ``off``; an empty or other value stops the
backend. Compose expands ``$NAME`` in unquoted and double-quoted values and
only warns when ``NAME`` is unset, so put a value that contains ``$``, such
as a secret key or a password, in single quotes.

.. list-table:: Required variables
   :header-rows: 1
   :widths: 35 20 45

   * - Variable
     - Required
     - Purpose
   * - ``ROLA_SECRET_KEY``
     - always
     - Django's signing key. Changing it invalidates outstanding activation
       and password-reset links and Django admin sessions. Links from the
       previous deployment do not work either way; see :doc:`transfer`.
   * - ``ALLOWED_HOSTS``
     - always
     - Comma-separated host names that the site answers to.
   * - ``ROLA_FRONTEND_URL``
     - always
     - The site's absolute ``https://`` address, used in account email
       links. The backend refuses anything but an absolute http or https
       URL.
   * - ``ROLA_POSTGRESQL_PASSWORD``
     - always
     - The database password; the ``db`` service is initialized with it.
   * - ``ROLA_NUM_PROXIES``
     - always
     - The number of proxies in front of Gunicorn, 2 in the standard setup.
       See `Client addresses`_.
   * - ``VITE_PAYPAL_CLIENT_ID``
     - always
     - The PayPal client id, built into the frontend.
   * - ``VITE_SENTRY_DSN``
     - always
     - The Sentry DSN for frontend error reports, built into the frontend.
   * - ``ROLA_DEFAULT_FROM_EMAIL``
     - when ``ROLA_USE_SES`` is on
     - The sender of account email. SES rejects Django's default sender.
   * - ``ROLA_SES_ACCESS_KEY_ID``, ``ROLA_SES_SECRET_ACCESS_KEY``
     - when ``ROLA_USE_SES`` is on
     - The SES SMTP credentials.
   * - ``ROLA_AWS_REGION_NAME``
     - when ``ROLA_USE_S3`` is on
     - The buckets' region. Media URLs are signed with SigV4 for this region.
   * - ``ROLA_AWS_MEDIA_STORAGE_BUCKET_NAME``,
       ``ROLA_AWS_STATIC_STORAGE_BUCKET_NAME``
     - when ``ROLA_USE_S3`` is on
     - The buckets for uploaded photographs and collected static files. The
       media bucket stays private, and the static bucket must be publicly
       readable. See `Maintenance`_.

``.env.example`` describes the optional variables: ``WEB_CONCURRENCY``,
``ROLA_APP_NAME``, ``ROLA_CSRF_TRUSTED_ORIGINS``,
``ROLA_USE_X_FORWARDED_HOST``, the SMTP host and port, and the S3 credentials
and endpoint.

Without ``ROLA_USE_SES``, the backend discards all email, so nobody can
activate an account or reset a password, and ``check --deploy`` reports
``mail.E001``.

The ``VITE_`` values are compiled into the frontend image when it is built.
After changing one, rebuild the frontend with ``docker compose build
frontend`` and start it again with ``docker compose up -d --wait``.

TLS terminator
==============

The frontend is published on ``127.0.0.1:8080`` only, for a TLS terminator on
the same server. The previous deployment published port 8080 on every
interface, so check where the terminator forwards to. The terminator must:

* terminate TLS and redirect plain HTTP to HTTPS;
* forward the ``Host`` header unchanged, because Django checks it against
  ``ALLOWED_HOSTS`` and the browser's ``Origin`` against it;
* set ``X-Forwarded-Proto`` to ``https``, replacing any value the client
  sent;
* append the client's address to ``X-Forwarded-For``;
* wait up to 120 seconds for a response;
* accept request bodies of up to 10 MiB.

With nginx as the terminator, the forwarding part looks like this:

.. code-block:: nginx

   client_max_body_size 10m;

   location / {
       proxy_pass http://127.0.0.1:8080;
       proxy_set_header Host $http_host;
       proxy_set_header X-Forwarded-Proto https;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_read_timeout 120s;
   }

The backend trusts ``X-Forwarded-Proto`` because ``ROLA_TRUST_PROXY`` is on,
and redirects every request that did not arrive over HTTPS. Without the
header, every request is redirected again, in a loop. Set
``ROLA_USE_X_FORWARDED_HOST`` only if the terminator replaces ``Host`` and
passes the original in ``X-Forwarded-Host``. Never publish the backend
itself: it trusts these headers from whoever sends them.

Client addresses
================

The login, registration and recovery limits count requests per client
address. Behind proxies, the backend takes that address from
``X-Forwarded-For``: it counts ``ROLA_NUM_PROXIES`` entries from the end of
the header, because each proxy appends the address it received the request
from. Set it to the number of proxies in front of Gunicorn: nginx and the TLS
terminator make 2, and every further proxy that appends to
``X-Forwarded-For``, such as a CDN or a load balancer, adds one.

* Too low, and every request seems to come from nginx or the terminator.
  All clients then share one budget, and 30 login attempts a minute from
  anyone lock everybody out of the API and the Django admin login.
* Too high, and the counted entry is one the client wrote itself, so a client
  can claim a new address for each request and is never limited.

Request limits
==============

* The API login (``POST /api/v1/user/login``), the Django admin login
  (``POST /django-admin/login/``) and password changes
  (``POST /api/v1/user/{id}/change_password``), which check the current
  password, share one budget of 30 attempts a minute per client address.
  Further attempts get 429 with ``Retry-After``.
* Registration and account activation each have their own budget of 60
  requests an hour per client address. Password-reset requests and
  confirmations share a budget of 30 requests an hour. Entrants behind one
  school or club network share these budgets.

The counters live in the ``rola_cache`` table, so all Gunicorn workers share
them. The Django admin is reachable from the internet; its login limit
slows password guessing, but staff accounts still need strong passwords.

HTTPS and headers
=================

Outside debug mode, the backend redirects HTTP to HTTPS, marks the session
and CSRF cookies secure, and sends ``Strict-Transport-Security`` with a
one-year ``max-age``, without ``includeSubDomains`` or ``preload``, because
it cannot know which subdomains serve HTTPS. The header comes with API and
admin responses. Once a browser has seen it, it uses only HTTPS for the host
for a year, so the site cannot move back to plain HTTP.
``manage.py check --deploy`` warns about the missing ``includeSubDomains``
and ``preload`` (``security.W005`` and ``security.W021``); that is intended.

nginx adds ``X-Frame-Options: DENY``, ``X-Content-Type-Options: nosniff``
and a ``Referrer-Policy`` to the files it serves, sends no version in
``Server``, and leaves proxied responses with Django's own security headers.

Contest content
===============

The confirmation page that entrants see after an upload shows the contest's
``confirmation_html`` as written and runs its scripts in the site's origin;
that is how the PayPal buttons are set up. Those scripts can read the login
token that the frontend keeps in the browser's local storage. Whoever can
change a contest can therefore run code in the browser of every entrant who
reaches that page, with the entrant's login: superusers, in the Django admin
and through the API, and staff accounts with the ``core.change_contest``
permission. Give that permission only to fully trusted staff. Contest notices
(``notice_html``) are sanitized before they are shown.

Uploads
=======

The frontend uploads each photograph in its own request. The backend accepts
JPEG files only, and rejects a photograph larger than 5 MiB, or with a longer
edge above 3500 pixels, with a validation message. nginx accepts request
bodies of up to 10 MiB, so a photograph slightly over the limit gets that
message instead of a bare 413; the TLS terminator must accept the same size.
nginx buffers request bodies, so a slow upload does not hold a Gunicorn
worker.

Judges and, once the results are published, anyone can download the stored
photographs, so the backend stores each without the metadata that could
identify its author or the place where it was taken. It keeps the compressed
image unchanged, so the photograph loses no quality, and the metadata that
displaying it needs: the JFIF header, the ICC colour profile, the Adobe
colour transform and the EXIF orientation. It drops every other EXIF tag,
such as the camera owner, the copyright holder and the GPS position, XMP and
IPTC data, comments, embedded thumbnails and further pictures in the file.
The thumbnail is made from the stripped photograph and turned upright by its
EXIF orientation, because the thumbnail itself carries no EXIF data.
``manage.py stripphotometadata`` strips the photographs and thumbnails stored
before, under the same names; the data transfer runs it (see
:doc:`transfer`). It does not turn the thumbnails made before upright.

Contest downloads
=================

The contest download is the Download button of a contest in the Django
admin, at ``/django-admin/contests/contest/<id>/download/``. It needs a staff
account that organizes the contest, or a superuser. It is the longest
request: the 120-second limits of Gunicorn, nginx and the TLS terminator are
set for it. The zip archive is not compressed, so it is as large as the
contest's photographs together. A backend worker reads every photograph from storage
and writes the archive to a temporary file in the backend container, so its
memory does not grow with the contest, but the server needs as much free
disk as the archive while the download runs. For 300 photographs of 3 MB,
the archive was 901 MB, and the worker's peak memory grew by 4 MiB with the
photographs on disk and by 35 MiB with them in S3. Gunicorn sends the file
with ``sendfile`` and logs the download with 0 bytes; nginx's access log
has its size.

Gunicorn cuts the download off if building the archive and passing it to
nginx takes longer than 120 seconds. With ``ROLA_USE_S3`` on, the worker
reads each photograph from the bucket, so the time depends on the
connection to S3: download the largest contest once after the first start
or the transfer, and check that it completes.

nginx keeps up to 4 GiB of the response in a temporary file of its own, so
the worker is free again before a slow browser has the whole archive, and
the server needs that much free disk again until the download completes. An
archive larger than 4 GiB holds the worker at the browser's pace until the
download is almost complete, and Gunicorn cuts it off if that takes longer
than 120 seconds. Each download that runs at the same time needs as much
disk again.

If a download does not complete, write the contest's archive on the server
instead. ``manage.py exportcontest`` writes the same archive as the download
to a new file in the backend container, with no time limit. It refuses a
path that exists already, and removes the file again if writing it fails.
The contest's id is the number in the address of its page in the Django
admin. The archive holds the entrants' photographs, so copy it into a
directory that no other account on the server can read, then remove it from
the container:

.. code-block:: shell

   docker compose exec backend python manage.py exportcontest <id> /tmp/<name>.zip
   install -d -m 700 ~/rola-export
   docker compose cp backend:/tmp/<name>.zip ~/rola-export/
   docker compose exec backend rm /tmp/<name>.zip

Until the ``rm``, the server needs as much free disk as the archive twice.

Workers
=======

Each Gunicorn worker handles one request at a time, including the account
emails that some requests send over SMTP, with a 10-second connection
timeout. Raise ``WEB_CONCURRENCY`` in ``.env`` when requests queue, for
example around a submission deadline; each worker is a separate process with
its own memory.

Gunicorn restarts a worker whose request takes longer than 120 seconds. The
longest request is the contest download; see `Contest downloads`_.

Account recovery
================

A password-reset request gets the same 200 response for unknown, inactive and
active addresses, but only an active account gets an email, and the request
sends it before answering. The response time can therefore still reveal
whether an address has an active account. The recovery limit slows such
probing; removing the difference would need asynchronous mail delivery.

Registration answers 201 with an empty body for every address. A new address
gets an activation link. An address that already has an account, active or
not, gets a password-reset link instead, and completing the reset activates
the account. Both paths hash the submitted password and send one email before
answering, so their response times are alike. Each registration of an
existing address therefore emails that account, limited like any
registration to 60 requests an hour per client address (`Request limits`_),
with no separate limit per recipient address.

Logs
====

nginx and Gunicorn write their access logs to the container output
(``docker compose logs``). Both record the path without the query string and
leave out the ``Referer``, because activation and password-reset links carry
their token in the query. Django logs request errors to the same output.

PostgreSQL logs its errors to the same output. ``compose.production.yaml``
starts it with ``log_error_verbosity=terse`` and
``log_min_error_statement=panic``, so the log keeps only the error message,
such as the name of a violated constraint. With the defaults, it would also
keep the failed statement and the error's detail, which hold the row's
values, such as a participant's email address, name or password hash.

nginx's error log goes to the same output. For a request that fails inside
nginx, for example while the backend is unreachable, it records the full
request line, query string included, and the ``Referer``. Such a line can hold
an activation or reset token, so treat the container output as confidential:
do not share it or forward it to a log service unfiltered.

First start
===========

For an empty database:

.. code-block:: shell

   docker compose pull db
   docker compose build --pull
   docker compose up -d --wait
   docker compose exec backend python manage.py check --deploy
   docker compose exec backend python manage.py createsuperuser

To start from the previous deployment's data, follow :doc:`transfer` instead,
and create no account before the transfer.

Upgrades
========

Check out the new revision, then:

.. code-block:: shell

   docker compose pull db &&
   docker compose build --pull &&
   docker compose run --rm migrate &&
   docker compose up -d --wait

The Compose files and Dockerfiles name exact image tags, and the images'
publishers rebuild those tags with operating-system security fixes. ``pull
db`` and ``build --pull`` fetch the current image for each tag, and ``run``
and ``up`` then recreate the containers whose image or service definition
changed. Without them, Docker keeps using the copies it pulled first.

``run`` runs the release command from the new image while the previous
backend still serves requests. If ``pull db`` fetched a new image, or the
new revision changes the ``db`` service in ``compose.production.yaml``,
``run`` first recreates the ``db`` container, and ``/api`` and the Django
admin answer with a server error until PostgreSQL accepts connections
again, usually after a few seconds.

If ``run`` fails, ``&&`` stops the commands before ``up``: the backend has
not been replaced and the previous release keeps serving. Do not run ``up``
until ``run`` succeeds, because ``up`` would replace the backend and run the
same failing ``migrate`` again, which leaves no backend serving.

``up`` replaces the backend and runs ``migrate`` again, which finds nothing
to apply. ``/api`` and the Django admin are unavailable from when
it stops the old backend until the new one starts serving, once ``migrate``
has finished and Gunicorn has started. ``--wait`` returns when the new
backend passes a health check, the first of which runs about 15 seconds
after it starts, or with an error if the new backend does not become
healthy.

If ``up`` fails, the previous backend is already gone. Check out the
previous revision, then run ``docker compose build`` and ``docker compose up
-d --wait`` to start it again. Checking out the previous revision does not
undo the new migrations, so a migration that changed the schema in a way the
previous release cannot use blocks this recovery.

Cutover from the previous deployment
====================================

* Set ``VITE_PAYPAL_CLIENT_ID`` and ``VITE_SENTRY_DSN`` to the values the
  previous frontend used. Its source had them hard-coded: the PayPal client
  id in the PayPal SDK script in ``frontend/public/index.html``, and the
  Sentry DSN in ``frontend/src/App.tsx``. Without the PayPal client id, the
  confirmation page shows no PayPal buttons.
* Transfer the data as :doc:`transfer` describes. It ends with pointing the
  TLS terminator at ``127.0.0.1:8080``, and everyone logs in again
  afterwards.

Maintenance
===========

* Django admin sessions stay in the database after they expire. Remove them
  regularly, for example weekly with this crontab line, for a checkout in
  ``/srv/rola``. cron starts in the home directory, so the line changes to
  the checkout, where ``.env`` selects the Compose file:

  .. code-block:: text

     0 4 * * 1 cd /srv/rola && docker compose exec -T backend python manage.py clearsessions

* Photographs uploaded by a form that failed or was abandoned stay stored
  without a submission, and so does an image whose delete failed; the
  backend logs ``Unable to delete stored image <name>.`` for it. Delete them
  weekly as well:

  .. code-block:: text

     0 4 * * 1 cd /srv/rola && docker compose exec -T backend python manage.py deleteorphanphotos

  The command deletes uploads that no submission holds, and the stored files
  in ``photos/`` and ``thumbs/`` that no upload references, once they are a
  day old, so uploads in progress and contest header images stay. It prints
  how many of each it deleted; ``--dry-run`` prints the counts and deletes
  nothing.
* The ``db`` and ``media`` volumes hold all state; ``collectstatic`` refills
  the ``static`` volume on every start. The application has no backup
  feature of its own.
* With ``ROLA_USE_S3`` on, photographs and static files are stored in the S3
  buckets instead of the volumes. Keep the media bucket private: the backend
  signs every photograph URL, and a signed URL is valid for one hour. Static
  file URLs are not signed, because the Django admin's stylesheets load their
  images by relative URLs, which cannot carry a signature. Give the static
  bucket a bucket policy that lets anyone read its objects:

  .. code-block:: json

     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Principal": "*",
           "Action": "s3:GetObject",
           "Resource": "arn:aws:s3:::<static bucket>/*"
         }
       ]
     }

  S3 Block Public Access refuses such a policy. On the static bucket only,
  turn off its two settings for bucket policies, ``BlockPublicPolicy`` and
  ``RestrictPublicBuckets``, and keep the two for ACLs on. S3 applies the
  stricter of the account's and the bucket's settings, so the account must
  have those two off as well. Leave Block Public Access fully on for the
  media bucket.
* A PostgreSQL major upgrade needs a dump and a restore into a new ``db``
  volume; pointing a newer image at the old volume does not work.
