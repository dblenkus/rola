Unreleased
==========

The backend moves to Django 6.1 and Django REST framework 3.18, the frontend
to React 19, React Router 8 and Redux Toolkit on Rola's own design system
with React Aria Components instead of MUI, and the deployment to current
images. The existing data moves to the new stack through a one-off
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
* Theme and submission results publish only entries in a paid submission
  set, as judging lists only those, and ``submissions_number`` in theme
  results counts only those. Theme results list their entries as
  ``ThemeSubmissionResults``, without ``rating``, the total score;
  ``/api/v1/results/submission`` keeps it. A result author's ``school`` is
  ``null`` unless the contest sets ``school_show``, and ``club`` unless it
  sets ``club_show``. The results used to include unpaid entries, theme
  results the score of every entry, accepted or not, and every author's
  school and club.
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
  Registering a domain-case variant of an existing address used to fail with
  500, and a local-part variant created a second account.
* Registration (``POST /api/v1/user``) answers 201 with an empty body for
  every address, instead of the new profile, or 400 "user with this email
  already exists." for an address that has an account. Such an address gets
  an email with a password-reset link instead of an activation link, and a
  password reset now also activates an inactive account, which used to get
  400 "Account is not activated, contact support.". Two registrations of one
  address at once no longer fail with 500.
* Activation and reset emails link to the frontend under
  ``ROLA_FRONTEND_URL``; the backend placeholder pages that answered 501 are
  gone.
* An activation link answers 200 each time it is used until it expires. Once
  the account was active it used to answer 400 "Bad token.", so opening the
  link again, or retrying after a lost response, reported it as invalid.
* The results of a published theme that has no results yet answer 404
  instead of 500.
* ``?submitted=`` on the contest list returns each contest once instead of
  once per submission.
* Paginated lists break ordering ties by primary key, so paging through a
  list sorted with ``?ordering=`` no longer repeats or skips rows.
* Validation errors for a batch submission, a list in the request body, are
  an object keyed by the index of each failing item instead of a list with an
  entry per item, as Django REST framework 3.18 reports them.
* Every error on a submission's ``files`` is a list of messages, as on the
  other fields. An upload deleted while a submission request attached it
  used to answer ``{"files": "An upload is no longer available."}``, with a
  string.
* Submissions can be created, changed and deleted only while their contest
  accepts entries: from its start date to its end date, and before its
  results are published. Outside that window these requests answer 403 with
  the detail "This contest is not accepting entries."; superusers can still
  delete a submission set until publication. Only the owner can change or
  delete a submission. An author can enter at most a theme's ``n_photos``
  photographs in it, and more answer 400. Submissions used to be accepted at
  any time and in any number, and could be changed or deleted until
  publication, also while the jury rated them.
* ``PUT``, ``PATCH`` and ``DELETE`` on ``/api/v1/author/{id}`` answer 403
  once the author has submissions in a contest that no longer accepts
  entries because it has ended or its results are published, and so does
  ``DELETE`` on ``/api/v1/user/{id}`` once the account has.
  These requests used to succeed at any time, so an entrant could delete
  entries that the jury was rating or the results showed, with their
  ratings and rewards, or change the name shown in the results.
* Deleting an account also deletes its postal address, which used to stay
  in the database after the account was gone. ``DELETE`` on
  ``/api/v1/user/{id}`` answers 409 for an account that a contest has as a
  judge, instead of failing with 500.
* A submission's author and photographs must belong to the requester, a
  photograph can belong to only one submission, and an update cannot change
  the author or the contest. Such requests answer 400.
* ``PUT`` and ``PATCH`` on ``/api/v1/submission/{id}`` delete the uploads
  that the new ``files`` list leaves out, with their stored photographs and
  thumbnails. They used to stay stored without a submission until the
  account was deleted.
* ``POST /api/v1/file`` accepts JPEG files only and answers 400 for another
  image format or a damaged JPEG file. Other formats used to be stored or to
  fail with 500, as a truncated JPEG file did. The stored photograph that
  ``file`` links to no longer carries the upload's identifying metadata.
* A submission request, single or batch, creates its submissions and their
  submission set in one transaction. An empty batch, a batch that mixes
  contests or authors, and a photograph used twice answer 400 and create
  nothing.
* ``POST /api/v1/submission`` accepts an optional ``Idempotency-Key`` header
  with a UUID. A request that repeats the key of an earlier upload by the
  same account creates nothing and sends no email: it answers 200 with that
  upload's submissions, also after the contest has closed. A key that is not
  a UUID answers 400. A retry after a lost response used to enter the
  submissions again and send a second confirmation email.
* Only a judge of the contest can create or change a rating, only for a paid
  submission, as the judging list shows, and only until the results are
  published, and a rating cannot move to another submission. Rating an
  unpaid submission used to succeed through the API, so its score counted
  towards acceptance in the results; now it answers 400, as does changing a
  rating after the submission's payment was revoked.
* A judge has one rating per submission. Two saves of a judge's first rating
  at once used to store two ratings, which the results added up and which
  made every later change of that rating fail with 500; now the later save
  updates the rating.
* A rating's score is an integer from 1 to 10, as the jury view offers, and
  other values answer 400. Any integer used to be stored, so a single score
  outside that range could outweigh all other judges in the totals that
  decide acceptance and ranking.
* The contest download moves from ``/core/contest/{id}/download`` into the
  Django admin, at ``/django-admin/contests/contest/{id}/download/``, so it
  needs a staff login, and it answers 403 to anyone but the contest's
  organizer and superusers. Its archive holds every photograph of each
  submission, read through the configured storage.
* The API sends no CORS headers; the frontend calls it from the same origin.
* ``/api-auth/``, Django REST framework's session login, is removed. The API
  accepts only the login token.
* The login token is sent as ``Authorization: Bearer <token>``.
  ``Authorization: Token <token>`` is no longer recognised: a request with it
  is handled as anonymous. A 401 carries ``WWW-Authenticate: Bearer``.
* A login token is ``rola_st_`` followed by 64 hexadecimal digits instead of
  40 hexadecimal digits, and a credential without that prefix answers 401
  "Invalid token".
* The database stores the SHA-256 digest of a login token instead of the
  token, so a token cannot be read from the ``accounts_token`` table or from
  a copy of the database.
* ``POST /api/v1/user/logout`` expires the login token that the request
  carries and answers 204 with an empty body. The account's other tokens
  stay valid, and a later request with the expired token answers 401. The
  API had no logout, so a token stayed valid until it expired, two days
  after the login.
* The API answers JSON only. Django REST framework's browsable HTML pages,
  whose forms showed any account the titles of every submission, are gone:
  ``?format=api`` answers 404 and a request that accepts only ``text/html``
  answers 406.
* ``?current=`` on the account list is described as a presence flag: any
  non-empty value limits the list to the caller's own account.
* ``backend/openapi.yaml`` describes the API, generated with the PostgreSQL
  backend's integer bounds; the backend serves no schema at runtime. Its
  security scheme ``tokenAuth`` is the HTTP ``bearer`` scheme.

Interface changes
-----------------

* Every page has the design system's look, with Inter and DM Mono served
  from the site instead of Roboto. The product is named "Rola" in the
  header and in each page's title, which also names the page.
* On a phone, the main navigation is a tab bar fixed to the bottom of the
  screen, and the upload page hides both bars and brings its own header and
  submit bar.
* The header offers both languages side by side. Request errors, upload
  validation, notifications and several page texts that were in English
  only are translated, and the page's ``lang`` follows the chosen language,
  so screen readers pronounce Slovenian text as Slovenian.
* Pages have main, banner and navigation landmarks, a skip link and one
  ``h1``, and focus moves to the main content after navigation.
* An API request without an answer fails after 30 seconds with its own
  message instead of waiting forever. A photograph upload has no time limit.
* An unknown address shows "Page not found" instead of an empty page, and a
  page that fails to render shows an error with Reload instead of a blank
  window.
* Dates read "15. 11. 2026" in Slovenian and "15 Nov 2026" in English, and
  the contest list and contest page show the days left to enter.
* Email fields are of type email, so a phone shows its email keyboard and
  the browser refuses an address without "@". The school lookup opens on
  focus and says in words that it is loading. The date of birth is entered
  as day, month and year instead of in a calendar.
* The upload page shows each photograph's size in pixels, how many
  photographs are chosen per theme and the rules a file must meet.
* Results mark awards with an award mark and the award's name instead of
  gold, silver and bronze row backgrounds, and accepted entries with a check
  and the word. Only an accepted entry's title is a link; whole rows are no
  longer clickable.
* The admin's paid toggle is a checkbox named after the author, and says
  "Paid" or "Not paid" on a phone, instead of a money icon in one of two
  colours. A submission set shows its photographs as thumbnails that link
  to the full files.
* A notification pauses its five seconds while the pointer is over it or
  focus is inside it.
* The judge's theme list shows each theme's progress, and the gallery shows
  each photograph's number and the judge's score as a figure instead of ten
  stars.
* The judge's scoring view takes the whole window. It has ten score keys,
  typed as the digits 1 to 9 and 0 for 10, Clear and Backspace to remove a
  score, Previous and Next, a filmstrip of the theme's photographs and a
  "Scored n / total" counter. Scoring a photograph no longer moves to the
  next one. The single-key shortcuts can be switched off, a choice the
  browser keeps, and are ignored while Ctrl, Alt or Meta is held or focus is
  in a text field.
* The app can be installed to a home screen. Offline, it opens to its shell
  with a notice instead of the browser's error page. Online, a reload or a
  new visit shows a new version at once, and a page that was open before the
  release announces the new version with a Reload prompt instead of being
  reloaded by itself.
* The interface has a dark theme. It follows the device, and the account
  menu's "Appearance" offers System, Light and Dark, a choice the browser
  keeps. The judge's scoring view looks the same in both.
* A contest's notice and confirmation text are shown in the interface's own
  colours and type. ``<style>`` and ``<font>`` elements, inline SVG and
  MathML, and the ``class``, ``data-`` and colour attributes in them are
  dropped. Of an inline style only alignment, weight, italics, the underline,
  width, an image's height, spacing, vertical alignment, white-space handling
  and list markers are kept.

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
* ``compose.tunnel.yaml``, merged after ``compose.production.yaml``,
  publishes the site through a Cloudflare Tunnel instead of a TLS terminator
  on the server. Its cloudflared service needs ``TUNNEL_TOKEN`` and reaches
  the frontend only, and with it the frontend's port is not published on the
  host, as "Cloudflare Tunnel" in ``docs/deployment.rst`` describes.
* Gunicorn serves the backend instead of Daphne. Redis, Channels, the backup
  worker and the backup feature are removed.
* The images run PostgreSQL 18.6 (from 12), Python 3.14.10, Node.js 26.13.1
  for the build, and nginx 1.30.6. Both application containers run as
  non-root users.
* nginx listens on port 8080, published on ``127.0.0.1`` only, and serves the
  frontend, media and static files itself; the separate proxy image is gone.
  It passes ``/api`` and ``/django-admin`` to Django, so the Django admin,
  with the contest download, is reachable from the internet; the proxy in
  ``deploy/nginx`` passed neither the admin nor the download. The Django
  admin login shares the API login's rate limit.
* The database is no longer published on port 5432 of every interface, where
  the old stack accepted connections without a password. The production stack
  publishes no database port; reach the database with ``docker compose exec
  db psql``.
* The database starts from new migrations. A database with the old migration
  history is refused, and the data moves with the transfer procedure.
* The apps have new labels, and their tables new names: ``drf_user_*``
  becomes ``accounts_*``, ``core_*`` becomes ``contests_*`` (contests,
  themes, institutions) or ``entries_*`` (authors, submission sets,
  submissions, files), ``payment_payment`` becomes ``payments_payment`` and
  ``rating_*`` becomes ``judging_*``. Constraint, index and sequence names
  follow the new labels, and the Django admin groups its models under
  Accounts, Contests, Entries, Payments and Judging. The transfer procedure
  maps the old names to the new ones.
* A ``migrate`` service runs ``migrate``, ``createcachetable`` and
  ``collectstatic`` on every start, before the backend. The ``rola_cache``
  table is required, and the backend health check fails without it.
* New optional variables: ``ROLA_CSRF_TRUSTED_ORIGINS``, and
  ``ROLA_SMTP_HOST`` and ``ROLA_SMTP_PORT``, which default to the SES
  endpoint in eu-west-1 on port 465 that the previous deployment had built
  in. The backend image sets ``ROLA_MEDIA_ROOT`` and ``ROLA_STATIC_ROOT``.
* New required variables: ``ROLA_FRONTEND_URL``, ``ROLA_NUM_PROXIES`` and
  ``VITE_SENTRY_DSN``, and ``ROLA_AWS_REGION_NAME`` when ``ROLA_USE_S3`` is
  on. The production stack also requires ``ROLA_SECRET_KEY``,
  ``ALLOWED_HOSTS`` and ``ROLA_POSTGRESQL_PASSWORD``.
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
  An account that registered before the transfer and was not activated can
  register again, which sends it a password-reset link that also activates
  it; the transfer procedure shows how to send a new activation link on
  request.
* S3 media URLs are signed with SigV4 for ``ROLA_AWS_REGION_NAME``.
* S3 static file URLs are no longer signed, so the Django admin's stylesheets
  can load their icons. The static bucket needs a bucket policy that allows
  public reads, as "Maintenance" in ``docs/deployment.rst`` describes; the
  media bucket stays private.
* nginx sends ``X-Frame-Options``, ``X-Content-Type-Options``,
  ``Referrer-Policy`` and a ``Content-Security-Policy`` that allows scripts
  from the site's own origin and inline scripts with a nonce that is new for
  every response, hides its version, caches hashed assets for a year, sends
  the application page with ``Cache-Control: no-store`` and answers its
  revalidation with the page instead of 304, and answers 404 for a missing
  asset instead of serving the application. A proxy or CDN that adds
  scripts to the pages must copy the nonce onto them, as Cloudflare's
  JavaScript Detections do, and must not cache the pages, as "HTTPS and
  headers" in ``docs/deployment.rst`` describes.
* The frontend build includes a service worker, ``/sw.js``, and a web app
  manifest, ``/site.webmanifest``, so browsers can install the site, which
  needs HTTPS. The worker stores only the app's own scripts, styles, fonts,
  icons, the manifest and ``index.html``. It gets the app's pages from
  nginx, and answers with the stored ``index.html`` only when nginx cannot
  be reached, except for ``/api``, ``/django-admin``, ``/media``, ``/static2``, ``/assets`` and
  file paths, which it leaves to the server. API responses and photographs
  always come from the network. A page that was open before a release keeps
  its version until the person presses Reload in the prompt, as "Releases
  and the service worker" in ``docs/deployment.rst`` describes.
* nginx serves ``/sw.js`` and ``/site.webmanifest`` with ``Cache-Control:
  no-cache``, the manifest as ``application/manifest+json``, and answers 404
  for a missing file at the root, such as an icon, instead of serving the
  application.
* The frontend makes no request to Google Fonts.
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
* ``manage.py exportcontest`` writes a contest's archive to a file on the
  server, with no time limit, for a contest whose download does not
  complete, as "Contest downloads" in ``docs/deployment.rst`` describes.
* ``manage.py deleteorphanphotos`` deletes uploads that no submission holds
  and stored photographs and thumbnails that no upload references, once they
  are a day old. Run it weekly, as "Maintenance" in ``docs/deployment.rst``
  describes; abandoned uploads used to stay stored indefinitely.
* CI no longer publishes images; they are built on the server.

Fixes
-----

* Logging out expires the login token on the server. It used to remove the
  token only from the browser's storage, so a copy of it kept working until
  it expired. A session that ends in another way (expiry, a token that the
  server rejected, a logout in another tab) sends no request.
* After an upload, opening another upload form in the same tab no longer
  jumps to the confirmation page.
* A failed upload releases the upload button and says that it failed, and an
  upload without photographs asks for one.
* An upload form in progress, with its photographs, survives a new login.
* An upload stops when another account signs in, in any tab, before it
  finishes, instead of sending the rest of the photographs and the author's
  details as that account.
* When a retried upload finds that the server had stored the earlier
  attempt after all, it says so and points to Edit submissions: changes
  made to the form since the lost response were not applied.
* Retrying an upload whose response was lost no longer enters its
  submissions a second time: every attempt from one upload form sends the
  same ``Idempotency-Key``.
* An upload or a submission delete that the server refuses because the
  contest has closed says so. A refused delete used to show a permission
  error, or nothing once the reload no longer listed the contest.
* A photograph removed or replaced in the upload form while it was still
  being read no longer comes back into the form when the read finishes.
* A photograph the browser cannot read, such as HEIC data saved as ``.jpg``,
  shows "Invalid file." in the upload form as soon as it is chosen. The form
  used to ignore it silently and keep the photograph chosen before.
* Clearing a title, or a series description, in the upload form no longer
  lets the upload through without it while photographs are selected.
* The upload form asks for the photo club when the contest requires it,
  instead of marking the field as required and uploading without it.
* A page that needs a login reloads when another account signs in, in any
  tab, instead of keeping the previous account's submissions, photographs
  and author details on screen.
* Public pages such as the contest list load without a login when the server
  has revoked the stored session, for example after a password change on
  another device, instead of failing once until the page is reloaded.
* A browser that blocks site data for the site shows the public pages, such
  as the contest list and results, instead of a blank page. Logging in there
  says that signing in needs site storage.
* A payment change in the admin submission list that finishes after the
  admin has moved to another page no longer shows every submission set on
  that page as unpaid.
* A jury gallery or rater link whose theme is not in the linked contest says
  that the content is no longer available instead of loading forever.
* A rating that finishes saving after the judge has left the rater no longer
  moves the next rater on, past a photograph or onto a spinner that never
  ends.
* The rater ignores a rating entered while the previous one is still being
  saved. Both used to be sent, and the server could store the earlier one
  last, after the rater had moved on as if the later one were stored.
* Holding a digit key in the rater rates only the photograph on screen. The
  key's repeats used to rate each following photograph the same, before the
  judge had seen it.
* The rater and the jury theme overview show every photograph of a series.
  They used to show only the first six, so a judge rated a longer series
  without seeing the rest.
* The rater reloads a theme's photograph links when a photograph fails to
  load, at most once a minute, and stays on the shown submission. Links to
  photographs in S3 expire an hour after the rater loads them, so a longer
  judging session used to show broken photographs until the page was
  reloaded.
* Deleting a submission or a submission set also deletes its photographs
  and thumbnails from storage, and so does deleting a contest or a theme in
  the Django admin.
* Stored photographs keep only the metadata that displaying them needs: the
  JFIF header, the colour profile, the Adobe colour transform and the EXIF
  orientation. The camera owner, copyright holder, GPS position and other
  EXIF tags, XMP and IPTC data, comments, embedded thumbnails and further
  pictures used to be stored as uploaded, and a comment was copied into the
  thumbnail, so judges could read the author's name and, after publication,
  anyone where a photograph was taken. ``manage.py stripphotometadata``
  strips photographs and thumbnails stored before; the transfer runs it.
* Thumbnails show photographs upright. A photograph whose EXIF orientation
  turns it for display, as phones store portrait photographs, used to get a
  thumbnail on its side, so the jury's theme gallery showed it sideways.
  Thumbnails made before are not turned upright.
* The jury view ignores late rating responses for a photograph it has already
  left.
* The jury gallery and rater show a theme only once they have loaded it:
  nothing from the theme opened before, no rating during the load, and
  neither the result nor the error of a load the judge has left.
* Contest notices and the confirmation text shown after an upload are
  sanitized: scripts, iframes, embedded objects, event-handler attributes
  and ``javascript:`` links are removed. Links that open in another window
  keep their ``target`` and get ``rel="noopener noreferrer"``. The
  confirmation text's scripts used to run in the site's origin, where they
  could read the entrant's login token. The PayPal buttons were set up by
  such scripts and are gone for now; the rest of the text still shows.
* Photograph file names with quotes or non-ASCII letters upload correctly.
* Screen readers hear the upload form's photograph preview as "Selected
  photograph" or "No photograph selected" instead of "Missing", and the
  preview and the file input are named in the interface language.
* Reset emails show names and the application name as written instead of
  with HTML escapes such as ``&amp;``.
* Theme results sort names in Slovenian alphabetical order and highlight an
  author's row only in the theme of the author's reward.
* The Django admin index no longer fails for an account without a first name.
* The Django admin's submission list and pages no longer fail when a
  submission has no title.
* The contest download sends a logged-out organizer to the Django admin
  login and back, instead of to a page that does not exist.
* A profile update that overlaps a password change or reset keeps the new
  password. It used to restore the old password and revive the reset links
  that the change had invalidated.
* A login with the old password that overlaps a password change or reset is
  refused. It used to receive a token that outlived the change, and an
  account whose stored hash the login upgraded got its old password back.
* A password change in the Django admin expires the account's login tokens
  and invalidates its outstanding reset links, as a change through the API
  does; both used to stay valid. Its attempts count against the login limit,
  which they used to bypass.
* The activation email greets with "Hello!" instead of the first name given
  at registration. Anyone can register any address, so that name could put a
  stranger's text and links into a genuine mail from the platform.
* The jury theme overview says "No published results." for a theme without
  published results. It lists only published results, and used to show an
  empty page before the contest's results were published.
* The page footer stays below the rater. The rater was laid over the page,
  so the footer was drawn behind the photographs, the description and the
  rating stars whenever they reached below the first screen.
* On a narrow screen, such as a 360 or 390 pixel wide phone, no page is
  wider than the screen. The header's buttons used to widen every page past
  it, so the account menu was cut off and the page scrolled sideways.
* A published series shows all of its photographs. The results used to drop
  every photograph after the sixth.
* The list of an entrant's submissions says in a line under the table, in
  both languages, that editing an entry is not available yet and how to
  change one. It used to say "Not jet available." in an English tooltip that
  only a mouse pointer could open.
* The upload form's message for a large photograph reads "Long edge should
  not exceed 3500px." instead of "Longe edge …".
* The admin's paid toggle has a name. It was an unnamed checkbox, which a
  screen reader announced without saying whose payment it changed.

Development changes
-------------------

* The backend is one ``rola`` distribution declared in
  ``backend/pyproject.toml`` and locked in ``backend/uv.lock``. Its packages
  ``rolca``, ``drf_user`` and ``utils`` become the apps ``rola.accounts``,
  ``rola.contests``, ``rola.entries``, ``rola.payments`` and
  ``rola.judging``, with ``rola.common`` for shared code and ``rola.config``
  for the settings, so ``DJANGO_SETTINGS_MODULE`` is
  ``rola.config.settings``. The tests are in ``backend/tests``. Ruff replaces
  black, flake8, isort and pydocstyle, and tox is gone.
* The frontend builds with Vite instead of Create React App, and npm with a
  lockfile replaces yarn. Its package is ``rola-frontend`` instead of
  ``rolca-ui``, and ``frontend/src`` is organized into ``app``, ``shared``
  and one directory per feature.
* The frontend is built on Rola's design system in ``frontend/src/design``
  and a component kit on React Aria Components in
  ``frontend/src/shared/ui``; MUI, Emotion, the MUI date pickers, Roboto and
  luxon are removed. ``npm run tokens`` generates ``tokens.css`` from
  ``tokens.json``, and ``npm run build`` fails while it is out of date.
* The frontend tests run as two Vitest projects: ``app`` under jsdom, and
  ``scripts`` under Node.js for the build scripts and the Vite
  configuration.
* New development dependencies: ``vite-plugin-pwa``,
  ``workbox-precaching`` and ``workbox-routing``, which build the service
  worker.
* The Django settings ``DRF_USER_*`` are named ``ACCOUNTS_*``, and
  ``ROLCA_MAX_UPLOAD_SIZE`` and ``ROLCA_MAX_UPLOAD_RESOLUTION`` are
  ``ENTRIES_MAX_UPLOAD_SIZE`` and ``ENTRIES_MAX_UPLOAD_RESOLUTION``. The
  ``ROLA_*`` environment variables keep their names.
* The ``Makefile`` in the repository root runs the checks that CI runs.
* The backend requires Python 3.14 or later.
* Lockfile updates accept only releases at least 7 days old, except
  Dependabot's npm security updates.
* CI tests the backend on Python 3.14 and 3.15 against PostgreSQL 18.6,
  checks the frontend, the API contract, both images, the Compose files,
  the workflows and the Dependabot configuration, and runs weekly with the
  dependency audits. Dependabot proposes updates for
  every manifest.
* The wheel declares its licences as ``AGPL-3.0-only AND Apache-2.0 AND
  BSD-3-Clause``.
