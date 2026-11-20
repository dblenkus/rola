==========
Deployment
==========

``compose.production.yaml`` runs Rola on one server behind a TLS terminator.
This page describes the services, their configuration, what the TLS
terminator must do, and how to start, upgrade and maintain the stack.
``compose.tunnel.yaml`` puts a Cloudflare Tunnel in the terminator's place;
see `Cloudflare Tunnel`_. The one-off move of the data from the previous
deployment is in :doc:`transfer`.

Run every command on this page from the repository root. The server's
``.env`` sets ``COMPOSE_FILE=compose.production.yaml`` (see `Configuration`_),
or both files for `Cloudflare Tunnel`_, so every ``docker compose`` command
run there uses the production stack.

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
   nginx as uid 101, published on ``127.0.0.1:8080`` unless
   ``compose.tunnel.yaml`` is used. It serves the
   built frontend, ``/media/`` from the ``media`` volume and ``/static2/``
   from the ``static`` volume, and passes ``/api`` and ``/django-admin`` to
   the backend. It looks up the backend's address again every 10 seconds, so
   it keeps working when the backend container is recreated. It waits up to 120 seconds for the backend's response and
   keeps up to 4 GiB of a response in a temporary file in its container;
   see `Contest downloads`_.

``tunnel``
   Only with ``compose.tunnel.yaml``: cloudflared as uid 65532, which
   connects out to Cloudflare and passes visitors' requests to the frontend.
   Its health check fails while it has no connection to Cloudflare. See
   `Cloudflare Tunnel`_.

The images are built on the server from the checked-out revision; no image is
published to a registry.

Configuration
=============

Copy ``.env.example`` to ``.env``, fill it in, and keep it out of Git. Keep
its ``COMPOSE_FILE`` line, which selects the production Compose file, or
use the one for `Cloudflare Tunnel`_.
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
   * - ``VITE_SENTRY_DSN``
     - always
     - The Sentry DSN for frontend error reports, built into the frontend.
   * - ``TUNNEL_TOKEN``
     - with ``compose.tunnel.yaml``
     - The Cloudflare Tunnel's token. See `Cloudflare Tunnel`_.
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

``VITE_SENTRY_DSN`` is compiled into the frontend image when it is built.
After changing it, rebuild the frontend with ``docker compose build
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

Cloudflare Tunnel
=================

``compose.tunnel.yaml`` publishes the site through a `Cloudflare Tunnel
<https://developers.cloudflare.com/tunnel/>`__ instead of a TLS terminator
on the server. Cloudflare terminates TLS and reads all traffic in clear
text. cloudflared, in the ``tunnel`` service, connects out to Cloudflare and
passes each request to the frontend, so the server needs no certificate and
no port that the internet can reach.

Merged after ``compose.production.yaml``, the file:

* adds the ``tunnel`` service, on a network that it shares with the frontend
  only, so that no route set in Cloudflare reaches the backend or the
  database;
* no longer publishes the frontend on ``127.0.0.1:8080``;
* gives ``migrate`` and ``backend`` an empty ``TUNNEL_TOKEN``, because
  ``env_file`` would otherwise hand them the token from ``.env``.

In Cloudflare, create a remotely managed tunnel and give it one route: the
site's host name, with the service ``http://frontend:8080``. The host name
belongs to a zone of the same Cloudflare account. Adding the route in the
dashboard creates the host name's DNS record, a CNAME to the tunnel, and
Cloudflare refuses the route while the host name has another A, AAAA or
CNAME record. Leave the route's HTTP Host Header setting empty, because
Django checks the unchanged ``Host`` (see `TLS terminator`_). Turn on Always
Use HTTPS for the zone, so that Cloudflare redirects plain HTTP itself. Then
change these lines of ``.env``:

.. code-block:: text

   COMPOSE_FILE=compose.production.yaml:compose.tunnel.yaml
   TUNNEL_TOKEN=<the tunnel's token>
   ROLA_NUM_PROXIES=2

Cloudflare sets ``X-Forwarded-Proto`` to the scheme the visitor used,
whatever the visitor sent, and appends the visitor's address to
``X-Forwarded-For``. cloudflared passes both on and adds nothing, and nginx
appends cloudflared's address, so Cloudflare and nginx are the 2 proxies
that ``ROLA_NUM_PROXIES`` counts (see `Client addresses`_).

Follow `First start`_ and `Upgrades`_ with ``docker compose pull db tunnel``
in place of ``docker compose pull db``. ``up --wait`` also waits until
cloudflared has a connection to Cloudflare. The site is public as soon as
the route exists and cloudflared has connected, which is before ``check
--deploy`` and ``createsuperuser`` in `First start`_; add the route
afterwards to keep the site closed until then. An upgrade that brings a new
cloudflared image restarts the ``tunnel`` service, and Cloudflare answers
visitors with an error page until it has connected again.

For :doc:`transfer`, create the tunnel and change ``.env`` while preparing
the new stack, but add no route yet: the host name's DNS record still points
at the old deployment. Where the transfer points the TLS terminator at
``127.0.0.1:8080``, delete that DNS record and add the route instead. To
roll back, remove the route and point the DNS record at the old deployment
again.

The token is all a connector needs. Every cloudflared that starts with it
joins the tunnel, and Cloudflare may send a visitor's request to any of
them, so run one stack with the token. If the token leaks, follow "Rotate a
compromised token" in Cloudflare's `tunnel token reference
<https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/>`__:
replace the token, then delete the tunnel's connections. Replacing the token
alone only refuses new connections, and a connector that has already joined
keeps receiving requests.

Behind Cloudflare, some limits differ from those of a terminator on the
server:

* Cloudflare waits 125 seconds for a response, and only its Enterprise plan
  can change that. Gunicorn's 120 seconds remain the limit for `Contest
  downloads`_.
* Cloudflare accepts request bodies of up to 100 MB on its Free and Pro
  plans, more than nginx's 10 MiB.
* Cloudflare caches ``/media/`` and ``/assets/`` files for as long as nginx
  tells browsers to keep them, a year. A photograph that was deleted on the
  server can therefore stay available at its address until it is purged from
  Cloudflare's cache. Cloudflare keeps ``/static2/`` files, which come
  without a cache header, for two hours, and tells browsers to keep them
  for the zone's Browser Cache TTL, four hours by default, so the Django
  admin's stylesheets and scripts can lag an upgrade by that long.
* Cloudflare compresses HTML and JSON responses on their way to the
  visitor. nginx leaves the responses of ``/api`` and ``/django-admin``
  uncompressed, so that the tokens in them are not exposed to compression
  side channels; a Compression Rule in Cloudflare that turns compression off
  for these two paths keeps it that way.
* The ``Content-Security-Policy`` that nginx sends (see `HTTPS and
  headers`_) makes browsers refuse the scripts that some Cloudflare features
  add to the site's pages. Cloudflare's `Content Security Policy reference
  <https://developers.cloudflare.com/fundamentals/reference/policies-compliances/content-security-policies/>`__
  lists what they need: Rocket Loader a script from ``ajax.cloudflare.com``,
  Web Analytics one from ``static.cloudflareinsights.com``, and Scrape
  Shield, whose Email Address Obfuscation Cloudflare enables automatically,
  inline scripts. `JavaScript Detections
  <https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/>`__,
  which are always on with Bot Fight Mode, add an inline script as well.
  Keep these features off for the site, or add the host they need to
  ``script-src`` in ``frontend/docker/default.conf`` and rebuild the
  frontend; allowing inline scripts would undo the policy.

Client addresses
================

The login, registration and recovery limits count requests per client
address. Behind proxies, the backend takes that address from
``X-Forwarded-For``: it counts ``ROLA_NUM_PROXIES`` entries from the end of
the header, because each proxy appends the address it received the request
from. Set it to the number of proxies in front of Gunicorn: nginx and the TLS
terminator make 2, and every further proxy that appends to
``X-Forwarded-For``, such as a CDN or a load balancer, adds one. With
``compose.tunnel.yaml``, Cloudflare and nginx make 2, because cloudflared
does not append to the header.

* Too low, and every request seems to come from nginx or the terminator.
  All clients then share one budget, and 30 login attempts a minute from
  anyone lock everybody out of the API login, the Django admin login and
  password changes.
* Too high, and the counted entry is one the client wrote itself, so a client
  can claim a new address for each request and is never limited.

Request limits
==============

* The API login (``POST /api/v1/user/login``), the Django admin login
  (``POST /django-admin/login/``) and password changes
  (``POST /api/v1/user/{id}/change_password`` and
  ``POST /django-admin/password_change/``), which check the current
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

nginx adds ``X-Frame-Options: DENY``, ``X-Content-Type-Options: nosniff``,
a ``Referrer-Policy`` and a ``Content-Security-Policy`` to the files it
serves, sends no version in ``Server``, and leaves proxied responses with
Django's own security headers.

The policy is ``script-src 'self'; object-src 'none'; base-uri 'self';
form-action 'self'``. With it, the site's pages run scripts from the site's
own origin only and no inline scripts, embed no plugins, and submit forms
only to the site itself. All of the application's scripts come from its own
origin. Anything else that puts an inline script, or a script from another
host, into the pages, such as a proxy or CDN feature that rewrites HTML, is
refused by the browser and breaks: turn it off, or extend the policy in
``frontend/docker/default.conf`` and rebuild the frontend. API and Django
admin responses do not carry the policy, because with ``ROLA_USE_S3`` the
Django admin's scripts come from the static bucket's host.

Contest content
===============

The frontend sanitizes a contest's notice (``notice_html``) and the
confirmation text that entrants see after an upload (``confirmation_html``)
before it shows them. It removes scripts, event-handler attributes, iframes
and embedded objects, and keeps formatting, links, images, forms and styles.
Whoever can change a contest therefore cannot run script in entrants'
browsers, but still decides which text, links and images those pages show:
superusers, in the Django admin and through the API, and staff accounts with
the ``contests.change_contest`` permission. Styles apply to the whole page,
so they can restyle or cover the rest of it, and images and stylesheets may
come from any host, which then sees the entrant's address.

Payment buttons are not supported for now. A payment provider's script in a
confirmation text does not run, and the policy in `HTTPS and headers`_ lets
a form submit only to the site itself.

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

A password change through the API, a reset link or the Django admin expires
the account's login tokens and invalidates the reset links already sent to
it. ``manage.py changepassword`` and a password written from
``manage.py shell`` do neither: the tokens and links stay valid until they
expire, tokens after two days and links after one. After such a change,
revoke them, filling in the address:

.. code-block:: shell

   docker compose exec -T backend python manage.py shell -c "
   from django.db.models import F
   from rola.accounts.models import Token, User
   user = User.objects.get(email__iexact='<address>')
   Token.objects.expire_for_user(user)
   User.objects.filter(pk=user.pk).update(password_reset_counter=F('password_reset_counter') + 1)
   "

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

With ``compose.tunnel.yaml``, cloudflared logs to the same output. It does
not log the requests it passes on, but for a request that it cannot pass to
the frontend, or that the visitor aborts, it records the full address, query
string included, so such a line can hold an activation or reset token too.
Cloudflare also streams cloudflared's log, with the address and headers of
every request, to account members who may edit the tunnel, in the dashboard
and through ``cloudflared tail``. Give that permission only to people who
may read the container output.

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

* Set ``VITE_SENTRY_DSN`` to the value the previous frontend used. Its
  source had the Sentry DSN hard-coded in ``frontend/src/App.tsx``.
* Transfer the data as :doc:`transfer` describes. It ends with pointing the
  TLS terminator at ``127.0.0.1:8080``, and everyone logs in again
  afterwards.
* The confirmation texts transferred from the previous deployment hold
  PayPal button markup, which no longer runs (see `Contest content`_), so
  the confirmation page shows their bank-transfer or other text without the
  buttons. :doc:`transfer` lists these contests; review their confirmation
  texts in the Django admin.

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
