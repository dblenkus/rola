==============================================
Transfer the data from the previous deployment
==============================================

The new stack does not upgrade the previous deployment's database. It
creates a new database from its own migrations, and this one-off procedure
copies the data into it. Read it to the end before starting.

Why a copy and not a migration
==============================

Each app now starts from a single migration, ``0001_schema``. The previous
database records the old migration chains, so ``migrate`` refuses it with
``InconsistentMigrationHistory`` before changing anything. The target must
therefore be a new, empty database that ``migrate`` created. With S3, the
new stack likewise gets new, empty buckets, and the photographs are copied
into them. The transfer writes nothing to the old buckets or media
directory, and changes the old database only where "Check the old data"
calls for a fix, so a rollback finds every photograph.

The copied tables have the same columns in the new schema, with nine
differences that decide how the data is copied:

* The tables have new names, because the apps have new labels (see `Old and
  new names`_). The procedure renames the tables in ``rola_old``, the scratch
  copy of the old database, and copies the data from there into the new
  database. It never renames anything in the old database, which a rollback
  needs as it is.
* Six columns have new names: ``n_photos`` in the themes, ``dob_required``,
  ``club_show`` and ``school_show`` in the contests, ``dob`` in the authors
  and ``submissionset_id`` in the payments (see `Old and new names`_). The
  procedure renames them in ``rola_old`` together with the tables.
* Seven tables (``entries_author``, ``contests_contest``,
  ``entries_submission``, ``entries_submissionset``, ``contests_theme``,
  ``judging_authorreward`` and ``judging_submissionreward``) order their
  columns differently. The copy must match columns by name. ``pg_restore``
  does, because ``pg_dump`` writes every ``COPY`` with its column list; a
  data-only plain dump with ``--inserts`` would not.
* ``entries_submissionset`` has a new column, ``upload_key``, which
  recognizes a repeated upload request. The old data has no such column, so
  the copied sets get ``NULL``, which the unique constraint
  ``entries_submissionset_unique_upload_key`` on the account and the key
  allows in any number of rows.
* Renaming a table keeps the names of its sequence, keys and indexes, and
  the old database names them after the old tables. The submission table
  started as ``core_photo``, so its sequence, keys and indexes are named
  ``core_photo_*`` there. The new database names every one of them after the
  new tables, such as ``entries_submission_id_seq``, so the ``SEQUENCE SET``
  entries of the dumps, for ``core_photo_id_seq`` among others, have no
  target. The copy therefore leaves out every ``SEQUENCE SET`` entry and
  resets all sequences from the copied keys afterwards. SQL written against
  the old object names does not work on the new database.
* The project's own tables have 64-bit primary keys; Django's
  ``auth_group``, ``auth_permission``, ``django_content_type`` and
  ``django_admin_log`` keep 32-bit keys. The old values copy unchanged.
* ``judging_rating`` holds at most one rating per judge and submission,
  through the unique constraint ``judging_unique_judge_submission``, and its
  ``rating`` column is a ``smallint`` from 1 to 10, through the check
  constraint ``judging_rating_between_1_and_10``. The old ``rating_rating``
  table had an ``integer`` column and neither constraint, and a single
  duplicate or out-of-range score makes the copy fail, so the old data is
  checked for both first.
* ``judging_judge`` holds at most one row per contest and account, through
  the unique constraint ``judging_unique_contest_judge``. The old
  ``rating_judge`` table had no such constraint, and a single account added
  twice as a judge of one contest makes the copy fail, so the old data is
  checked for that first too.
* ``contests_contest`` keeps a required club or school visible, through the
  check constraints ``contests_club_required_is_visible`` and
  ``contests_school_required_is_visible``. The old ``core_contest`` table
  had neither, and its Django admin set only ``club_required`` and
  ``school_required``, while ``club_show`` and ``school_show`` were added
  later as false for every contest. A single contest with a required but
  hidden club or school makes the copy fail, so the old data is checked for
  that first as well.

Content types and permissions are created by ``migrate`` and get new ids, so
their tables are not copied. The group and user permissions are remapped
through their natural keys (app label, model and codename) instead, after
the old app labels are changed to the new ones in ``rola_old``.

Login tokens, Django admin sessions and the admin log are not copied, so
everyone logs in again after the transfer. ``accounts_token`` also has
different columns from the old ``drf_user_token``: it stores the SHA-256
digest of each token under a numeric key, where the old table stored the
token itself as the key, so the old rows would not fit it. Email addresses
are stored in lowercase, so two accounts whose addresses differ only in case
must be resolved by hand before the transfer.

Rehearse the whole procedure before the real transfer, on copies of the old
database and photographs, with buckets that the real transfer does not use.
The production database holds entrants' personal data, so a rehearsal
outside an environment approved for that data uses synthetic data only.
Before the real transfer, reset a new stack that a rehearsal filled, as
"Prepare the new stack" describes.

Old and new names
=================

Every table's name takes the new app label as prefix, and every table except
``accounts_token``, which is not copied, keeps its columns, apart from the six
renamed columns listed after the tables; the many-to-many tables follow their
model's table. A table that is not listed here, such as ``auth_group`` or
``django_session``, keeps its name:

.. list-table::
   :header-rows: 1

   * - Old table
     - New table
   * - ``drf_user_email``, ``drf_user_location``, ``drf_user_token``,
       ``drf_user_user``, ``drf_user_user_groups``,
       ``drf_user_user_user_permissions``
     - ``accounts_email``, ``accounts_location``, ``accounts_token``,
       ``accounts_user``, ``accounts_user_groups``,
       ``accounts_user_user_permissions``
   * - ``core_contest``, ``core_institution``, ``core_theme``
     - ``contests_contest``, ``contests_institution``, ``contests_theme``
   * - ``core_author``, ``core_file``, ``core_submission``,
       ``core_submissionset``, ``core_submissionset_submissions``
     - ``entries_author``, ``entries_file``, ``entries_submission``,
       ``entries_submissionset``, ``entries_submissionset_submissions``
   * - ``payment_payment``
     - ``payments_payment``
   * - ``rating_authorreward``, ``rating_judge``, ``rating_rating``,
       ``rating_submissionreward``, ``rating_themeresults``
     - ``judging_authorreward``, ``judging_judge``, ``judging_rating``,
       ``judging_submissionreward``, ``judging_themeresults``

Six columns have new names. The other columns of their tables keep theirs:

.. list-table::
   :header-rows: 1

   * - Old column
     - New column
   * - ``core_theme.n_photos``
     - ``contests_theme.max_photos``
   * - ``core_contest.dob_required``
     - ``contests_contest.date_of_birth_required``
   * - ``core_contest.club_show``
     - ``contests_contest.club_visible``
   * - ``core_contest.school_show``
     - ``contests_contest.school_visible``
   * - ``core_author.dob``
     - ``entries_author.date_of_birth``
   * - ``payment_payment.submissionset_id``
     - ``payments_payment.submission_set_id``

The many-to-many table ``entries_submissionset_submissions`` keeps its
``submissionset_id`` column.

The app labels in ``django_content_type``, which the permissions' natural
keys hold, change the same way:

.. list-table::
   :header-rows: 1

   * - Old app label
     - New app label
   * - ``drf_user``
     - ``accounts``
   * - ``core``
     - ``contests`` for the models ``contest``, ``institution`` and
       ``theme``; ``entries`` for ``author``, ``file``, ``submission`` and
       ``submissionset``
   * - ``payment``
     - ``payments``
   * - ``rating``
     - ``judging``

The constraints that the project names itself take the new label too:
``core_submissionset_unique_upload_key`` becomes
``entries_submissionset_unique_upload_key``, ``rating_unique_judge_submission``
becomes ``judging_unique_judge_submission``, and
``rating_rating_between_1_and_10`` becomes
``judging_rating_between_1_and_10``. ``unique_name_kind`` on the institutions
keeps its name. ``judging_unique_contest_judge`` on the judges is new, and
so are ``contests_club_required_is_visible`` and
``contests_school_required_is_visible`` on the contests.
The names that Django generates for keys, indexes and sequences start with
the new table names, and their hash suffixes differ.

Until "Rename the tables and columns in the scratch copy", the old database
and ``rola_old`` use the old names, and the commands before that step name
the old tables and columns. From that step on, the commands use the new
names.

Prepare the new stack
=====================

Check out the new revision in a new directory. If the old deployment runs
from a checkout of this repository, leave that directory, with its
``docker-compose.yml`` and ``.env``, untouched until a rollback is no longer
needed: the old deployment's own Compose commands, which stop it and restart
it, run from there.

Set up the server and ``.env`` as :doc:`deployment` describes, including the
``COMPOSE_FILE`` line and the cutover value of ``VITE_SENTRY_DSN``, and
leave the TLS terminator pointing at the old deployment. Run every command
from the repository root, in one shell.

With ``ROLA_USE_S3`` on, the new stack gets new, empty buckets. Set
``ROLA_AWS_MEDIA_STORAGE_BUCKET_NAME`` and
``ROLA_AWS_STATIC_STORAGE_BUCKET_NAME`` to them, never to the old
deployment's buckets, which it names in the same variables. Give the new
stack credentials that have no access to the old buckets, not the old
deployment's ``ROLA_AWS_ACCESS_KEY_ID``. In shared buckets, the new stack
would delete the stored photographs of every submission deleted on it,
which the old database still references after a rollback, and its
``migrate`` service would write the new static files over the ones the old
Django admin serves. ``migrate`` fills the new static bucket; the
photographs are copied into the new media bucket after the freeze.

The dump of the old database holds the entrants' personal data, including
minors', with their password hashes and login tokens. No other account on
the server may read it, and it must not end up in the checkout, where
``git add -A`` would stage it. Keep it, and every other file that this
procedure writes, in a private directory outside the checkout. Start the
shell with:

.. code-block:: shell

   umask 077
   TRANSFER=~/rola-transfer
   install -d -m 700 "$TRANSFER"

Start the same way in the shell on every other machine that makes or
receives a copy of the old data, such as the old server. Then build the new
stack and create its database:

.. code-block:: shell

   docker compose pull db
   docker compose build --pull
   docker compose up -d --wait db
   docker compose run --rm migrate

The database must hold no accounts: do not run ``createsuperuser`` before the
transfer. This must print 0:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola -Atc "SELECT count(*) FROM accounts_user"

If it prints anything else, an earlier rehearsal or abandoned run filled the
new stack, and the copy would fail on its rows. Reset the new stack. Run
this in the new checkout only, never in the old deployment's directory: it
deletes the new stack's ``db``, ``media`` and ``static`` volumes, and with
the ``db`` container the scratch database and the files in its ``/tmp``:

.. code-block:: shell

   docker compose down -v

Then run ``docker compose up -d --wait db`` and ``docker compose run --rm
migrate`` again, and this check again. With ``ROLA_USE_S3`` on, also empty
the new media bucket before the photographs are copied into it, and never
the old one. ``migrate`` fills the new static bucket again, so emptying that
one is optional:

.. code-block:: shell

   aws s3 rm s3://<new media bucket> --recursive

The ``migrate`` service also installs the pgcrypto extension, which judging
needs. In the ``db`` service the ``rola`` role may do that; on another
PostgreSQL server the role needs the ``CREATE`` privilege on the database.

Freeze and dump the old deployment
==================================

#. Stop the old deployment's web server, so that no registration, upload or
   rating arrives after the dump. Leave its database running.
#. Dump the old database with the PostgreSQL 18 client, in the custom format,
   from a machine that can reach it. Fill in the old server's host, user and
   database. If the old database runs in Docker on the same server, add
   ``--network`` with its network to ``docker run``. If it needs a password,
   type it after the first command, which reads it without echoing it or
   putting it in the shell history; otherwise leave out the first and last
   commands. ``docker run -e PGPASSWORD`` passes the variable only when it is
   exported:

   .. code-block:: shell

      read -rs PGPASSWORD && export PGPASSWORD
      docker run --rm -e PGPASSWORD postgres:18.6-alpine3.24 \
          pg_dump -Fc -h <old host> -U <old user> -d <old database> > "$TRANSFER/rola-old.dump"
      unset PGPASSWORD

#. If the old deployment kept photographs on disk, archive its media
   directory with the paths relative to it, as the database stores them (for
   example ``photos/<name>.jpg``):

   .. code-block:: shell

      tar -C <old media directory> -cf "$TRANSFER/rola-media.tar" .

   For a Docker volume, run it in a container that mounts the volume
   read-only and the transfer directory for the archive:

   .. code-block:: shell

      docker run --rm -v <old media volume>:/old-media:ro -v "$TRANSFER":/work -w /work \
          postgres:18.6-alpine3.24 tar -C /old-media -cf rola-media.tar .

   If it kept them in S3, there is nothing to archive. Copy every object of
   the old media bucket into the new one under the same key, with the AWS
   CLI and credentials that may read the old bucket and write the new one.
   The copy only reads the old bucket; if it fails, run it again, and it
   copies only what is still missing:

   .. code-block:: shell

      aws s3 sync s3://<old media bucket> s3://<new media bucket>

Copy ``rola-old.dump``, and ``rola-media.tar`` if you made one, into the
transfer directory on the new server.

Check the old data
==================

Restore the dump into a scratch database next to the new one, replacing one
left from an earlier attempt. The checks and the permission remapping read
from it, and the copy comes from it once its tables and columns are renamed.
Until then it has the old names, as the old database does, and the checks
below use them:

.. code-block:: shell

   docker compose cp "$TRANSFER/rola-old.dump" db:/tmp/rola-old.dump
   docker compose exec -T db dropdb -U rola --if-exists rola_old
   docker compose exec -T db createdb -U rola rola_old
   docker compose exec -T db pg_restore -U rola -d rola_old --no-owner --no-acl \
       --exit-on-error /tmp/rola-old.dump

Look for email addresses that differ only in case. This must print no rows:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola_old -c \
       "SELECT lower(email) AS email, count(*) FROM drf_user_user GROUP BY lower(email) HAVING count(*) > 1"

If it prints any, stop. List the accounts involved with this query, decide
for each pair which address to change, change it in the old database, and
start again from the dump. Never merge accounts automatically: each one owns
its own submissions.

.. code-block:: sql

   SELECT internal_id, email, is_active, last_login, date_joined
   FROM drf_user_user
   WHERE lower(email) IN (
       SELECT lower(email) FROM drf_user_user GROUP BY lower(email) HAVING count(*) > 1
   )
   ORDER BY lower(email), internal_id;

Look for accounts that are a judge of the same contest more than once, which
the new schema refuses. Run this check, and its fix, before the check for
duplicate ratings, because the fix can leave a judge with two ratings of one
submission. This must print no rows:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola_old -c \
       "SELECT j.contest_id, c.title, j.judge_id, array_agg(j.id ORDER BY j.id) AS judge_rows FROM rating_judge j JOIN core_contest c ON c.id = j.contest_id GROUP BY 1, 2, 3 HAVING count(*) > 1 ORDER BY 1, 3"

If it prints any, stop. Each printed contest lists that account among its
judges more than once, and each of those judge rows may hold ratings. In the
old database, keep the judge row with the lowest id of each contest and
account (the first id in ``judge_rows``), move the ratings of the others to
it, and delete the others, in one transaction. Fill in the old server as for
the dump, with ``--network`` and the password lines if the dump needed them.
Then start again from the dump:

.. code-block:: shell

   read -rs PGPASSWORD && export PGPASSWORD
   docker run --rm -i -e PGPASSWORD postgres:18.6-alpine3.24 \
       psql -v ON_ERROR_STOP=1 -h <old host> -U <old user> -d <old database> <<'SQL'
   BEGIN;
   UPDATE rating_rating r SET judge_id = kept.id
   FROM rating_judge extra
   JOIN (SELECT contest_id, judge_id, min(id) AS id FROM rating_judge GROUP BY 1, 2) kept
       ON kept.contest_id = extra.contest_id AND kept.judge_id = extra.judge_id
   WHERE r.judge_id = extra.id AND extra.id <> kept.id;
   DELETE FROM rating_judge extra USING rating_judge kept
   WHERE kept.contest_id = extra.contest_id AND kept.judge_id = extra.judge_id
       AND kept.id < extra.id;
   COMMIT;
   SQL
   unset PGPASSWORD

The account now has one judge row in each contest, holding all its ratings
there. Where two of the merged rows had rated the same submission, the
account now has two ratings of it, which the next check finds.

Look for judges with more than one rating of the same submission, which the
new schema refuses. This must print no rows:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola_old -c \
       "SELECT judge_id, submission_id, count(*) FROM rating_rating GROUP BY 1, 2 HAVING count(*) > 1"

If it prints any, stop. The previous deployment stored a second rating when a
judge's first rating of a submission was saved twice at once, and its results
add up both. Merging duplicate judges leaves one too where two of the merged
rows had rated the same submission. List the contests involved for their
organizers: once one rating of each pair remains, the totals of the affected
entries change, and with them possibly which entries are accepted.

.. code-block:: sql

   SELECT DISTINCT c.id, c.title
   FROM (SELECT judge_id FROM rating_rating GROUP BY judge_id, submission_id HAVING count(*) > 1) d
   JOIN rating_judge j ON j.id = d.judge_id
   JOIN core_contest c ON c.id = j.contest_id
   ORDER BY c.id;

Then, in the old database, delete all but the most recently modified rating
of each pair, which holds the judge's last score. Fill in the old server as
for the dump, with ``--network`` and the password lines if the dump needed
them. Then start again from the dump:

.. code-block:: shell

   read -rs PGPASSWORD && export PGPASSWORD
   docker run --rm -i -e PGPASSWORD postgres:18.6-alpine3.24 \
       psql -v ON_ERROR_STOP=1 -h <old host> -U <old user> -d <old database> <<'SQL'
   DELETE FROM rating_rating r USING rating_rating newer
   WHERE newer.judge_id = r.judge_id AND newer.submission_id = r.submission_id
       AND (newer.modified, newer.id) > (r.modified, r.id);
   SQL
   unset PGPASSWORD

Look for scores outside 1 to 10, which the new schema refuses. This must
print no rows:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola_old -c \
       "SELECT id, rating FROM rating_rating WHERE rating NOT BETWEEN 1 AND 10"

If it prints any, stop. The jury view has only ever sent scores from 1 to
10, so such a score came from a direct API request. Ask the organizer of its
contest for the correct score, set it or delete the rating in the old
database as for the duplicates, and start again from the dump.

Look for contests that require the club or the school without showing it,
which the new schema refuses. ``club`` and ``school`` say which of the two is
required but hidden, and ``entries_closed`` whether the contest has stopped
accepting entries, because its end date or its publish date has passed.
This must print no rows:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola_old -c \
       "SELECT id, title, start_date, end_date, publish_date, club_required AND NOT club_show AS club, school_required AND NOT school_show AS school, now() > end_date OR now() >= publish_date AS entries_closed FROM core_contest WHERE (club_required AND NOT club_show) OR (school_required AND NOT school_show) ORDER BY id"

If it prints any, stop. The new upload form requires a required field even
where it hides it, so it would refuse every entry of such a contest. The new
results publish an author's club or school only where the contest shows it,
whichever fix is chosen, while the previous deployment sent every author's
club and school with the results whatever these settings said, and its admin
could not set ``club_show`` or ``school_show``. Expect older contests here.
Choose one of two fixes for each printed contest and field:

* Clear the requirement (``club_required`` or ``school_required`` false).
  The field stays hidden: the upload form no longer asks for it, and the new
  results do not publish it. Choose this for a contest whose entries are
  closed, unless its organizer wants the clubs or schools to stay in its
  published results.
* Show the field (``club_show`` or ``school_show`` true). The upload form
  asks every entrant for it, and the new results of the contest publish
  every author's club or school, those of the earlier entries included.
  Choose this for a contest whose entries are open or not yet open and whose
  organizer wants the field asked and published, and for a closed contest
  whose results should keep showing it.

Neither fix loses an author's club or school, and the contest admin of the
new stack can change the choice later.

Then make the fixes in the old database, in one transaction. Replace each
``<ids>`` with the comma-separated ids of the contests that get that fix
for that field, such as ``12,15``, or with nothing, leaving ``'{}'``, for a
fix that no contest gets. Each statement changes only a
contest whose field is still required and hidden, so a contest named twice
for one field gets only the first fix. Fill in the old server as for the
dump, with ``--network`` and the password lines if the dump needed them.
Then start again from the dump:

.. code-block:: shell

   read -rs PGPASSWORD && export PGPASSWORD
   docker run --rm -i -e PGPASSWORD postgres:18.6-alpine3.24 \
       psql -v ON_ERROR_STOP=1 -h <old host> -U <old user> -d <old database> <<'SQL'
   BEGIN;
   UPDATE core_contest SET club_required = false
   WHERE id = ANY ('{<ids>}'::bigint[]) AND club_required AND NOT club_show;
   UPDATE core_contest SET school_required = false
   WHERE id = ANY ('{<ids>}'::bigint[]) AND school_required AND NOT school_show;
   UPDATE core_contest SET club_show = true
   WHERE id = ANY ('{<ids>}'::bigint[]) AND club_required AND NOT club_show;
   UPDATE core_contest SET school_show = true
   WHERE id = ANY ('{<ids>}'::bigint[]) AND school_required AND NOT school_show;
   COMMIT;
   SQL
   unset PGPASSWORD

psql prints ``UPDATE <n>`` for each statement, the number of contests it
changed; the four numbers add up to the number of ``t`` values in the
check's ``club`` and ``school`` columns. On the scratch copy restored from
the new dump, the check must print no rows.

List the contests whose notice or confirmation text holds content that the
frontend now removes before it shows them: scripts, such as those of the
PayPal buttons, iframes, embedded objects, ``link``, ``meta`` and ``base``
elements, a ``style`` block at the start, event-handler attributes such as
``onclick``, and ``javascript:`` links. The list also has the contests with a
form, which now submits only to the site itself. After the switch, open each
listed contest and its confirmation page (``/contest/<id>/confirm``) on the
new site, and if a text lost something that matters, rewrite it in the Django
admin:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola_old -c \
       "SELECT id, title FROM core_contest WHERE concat(notice_html, ' ', confirmation_html) ~* '<(iframe|object|embed|script|style|link|meta|base|frame|form)|<[^>]*\son[a-z]+\s*=|javascript:' ORDER BY id"

List the published contests with entries that are in no paid submission
set, with how many such entries each has and how many of them were rated or
rewarded. The results now publish only paid entries, as judging lists only
those, so these entries disappear from the results of the listed contests.
Tell their organizers before the switch:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola_old <<'SQL'
   SELECT c.id, c.title, count(*) AS unpaid_entries,
       count(*) FILTER (
           WHERE EXISTS (SELECT 1 FROM rating_rating r WHERE r.submission_id = s.id)
               OR EXISTS (SELECT 1 FROM rating_submissionreward w WHERE w.submission_id = s.id)
       ) AS rated_or_rewarded
   FROM core_submission s
   JOIN core_theme t ON t.id = s.theme_id
   JOIN core_contest c ON c.id = t.contest_id
   WHERE c.publish_date <= now()
       AND EXISTS (SELECT 1 FROM rating_themeresults tr WHERE tr.theme_id = t.id)
       AND NOT EXISTS (
           SELECT 1 FROM core_submissionset_submissions m
           JOIN payment_payment p ON p.submissionset_id = m.submissionset_id
           WHERE m.submission_id = s.id AND p.paid
       )
   GROUP BY c.id, c.title
   ORDER BY c.id;
   SQL

Rename the tables and columns in the scratch copy
=================================================

Rename the old tables and the six renamed columns in ``rola_old`` to the new
names, and change the old app labels of its content types to the new ones
(see `Old and new names`_), in one transaction. The column renames name the
tables by their new names, because they run after the table renames. Run
this against ``rola_old`` only, never against the old database. A content
type of a ``core`` model that is not listed keeps its old label, so the
permission remapping lists its permissions:

.. code-block:: shell

   docker compose exec -T db psql -v ON_ERROR_STOP=1 -U rola -d rola_old <<'SQL'
   BEGIN;
   ALTER TABLE drf_user_email RENAME TO accounts_email;
   ALTER TABLE drf_user_location RENAME TO accounts_location;
   ALTER TABLE drf_user_token RENAME TO accounts_token;
   ALTER TABLE drf_user_user RENAME TO accounts_user;
   ALTER TABLE drf_user_user_groups RENAME TO accounts_user_groups;
   ALTER TABLE drf_user_user_user_permissions RENAME TO accounts_user_user_permissions;
   ALTER TABLE core_contest RENAME TO contests_contest;
   ALTER TABLE core_institution RENAME TO contests_institution;
   ALTER TABLE core_theme RENAME TO contests_theme;
   ALTER TABLE core_author RENAME TO entries_author;
   ALTER TABLE core_file RENAME TO entries_file;
   ALTER TABLE core_submission RENAME TO entries_submission;
   ALTER TABLE core_submissionset RENAME TO entries_submissionset;
   ALTER TABLE core_submissionset_submissions RENAME TO entries_submissionset_submissions;
   ALTER TABLE payment_payment RENAME TO payments_payment;
   ALTER TABLE rating_authorreward RENAME TO judging_authorreward;
   ALTER TABLE rating_judge RENAME TO judging_judge;
   ALTER TABLE rating_rating RENAME TO judging_rating;
   ALTER TABLE rating_submissionreward RENAME TO judging_submissionreward;
   ALTER TABLE rating_themeresults RENAME TO judging_themeresults;
   ALTER TABLE contests_theme RENAME COLUMN n_photos TO max_photos;
   ALTER TABLE contests_contest RENAME COLUMN dob_required TO date_of_birth_required;
   ALTER TABLE contests_contest RENAME COLUMN club_show TO club_visible;
   ALTER TABLE contests_contest RENAME COLUMN school_show TO school_visible;
   ALTER TABLE entries_author RENAME COLUMN dob TO date_of_birth;
   ALTER TABLE payments_payment RENAME COLUMN submissionset_id TO submission_set_id;
   UPDATE django_content_type SET app_label = CASE
       WHEN app_label = 'drf_user' THEN 'accounts'
       WHEN app_label = 'payment' THEN 'payments'
       WHEN app_label = 'rating' THEN 'judging'
       WHEN model IN ('contest', 'institution', 'theme') THEN 'contests'
       WHEN model IN ('author', 'file', 'submission', 'submissionset') THEN 'entries'
       ELSE app_label
   END
   WHERE app_label IN ('drf_user', 'core', 'payment', 'rating');
   COMMIT;
   SQL

If a table or column is missing, the transaction stops and renames nothing:
find out why before going on. This must print no rows, or a table of the old
schema was left with its old name:

.. code-block:: shell

   docker compose exec -T db psql -U rola -d rola_old -c \
       "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name ~ '^(drf_user|core|payment|rating)_'"

Dump the data of the renamed copy, so that the restore finds every table
under its new name:

.. code-block:: shell

   docker compose exec -T db pg_dump -U rola -d rola_old -Fc --data-only -f /tmp/rola-renamed.dump

Name the tables to copy, in a variable that the later steps use too, and
check that the dump holds no table that this procedure does not know. The
second command must print nothing and exit with status 0. It skips
``backup_filebackup``, from the removed backup feature, which is not copied.
If it prints a table, it exits with status 1: find out what that table holds
before going on.

.. code-block:: shell

   COPIED='auth_group|accounts_location|accounts_email|accounts_user|accounts_user_groups|entries_author|contests_contest|entries_file|contests_institution|entries_submission|entries_submissionset|entries_submissionset_submissions|contests_theme|payments_payment|judging_authorreward|judging_judge|judging_rating|judging_submissionreward|judging_themeresults'
   docker compose exec -T db sh -c "pg_restore -l /tmp/rola-renamed.dump > /tmp/rola-renamed.list && ! grep ' TABLE DATA ' /tmp/rola-renamed.list | grep -vE ' TABLE DATA public ($COPIED|auth_group_permissions|accounts_user_user_permissions|auth_permission|django_content_type|django_migrations|django_session|accounts_token|django_admin_log|backup_filebackup) '"

Copy the data
=============

#. Restore only the ``TABLE DATA`` entries of the copied tables from the
   renamed dump, in one transaction. The list file must have 19 lines:

   .. code-block:: shell

      docker compose exec -T db sh -c "grep -E ' TABLE DATA public ($COPIED) ' /tmp/rola-renamed.list > /tmp/restore.list && wc -l < /tmp/restore.list"
      docker compose exec -T db pg_restore -U rola -d rola --single-transaction \
          --exit-on-error -L /tmp/restore.list /tmp/rola-renamed.dump

   The foreign keys are checked when the transaction commits, so the order
   of the tables does not matter. If anything fails, nothing is written.

#. Store the email addresses in lowercase:

   .. code-block:: shell

      docker compose exec -T db psql -U rola -d rola -c \
          "UPDATE accounts_user SET email = lower(email) WHERE email <> lower(email)"

#. Remap the group and user permissions by natural key. Export them from the
   scratch database, whose content types have the new app labels:

   .. code-block:: shell

      docker compose exec -T db psql -v ON_ERROR_STOP=1 -U rola -d rola_old <<'SQL'
      \copy (SELECT gp.group_id, ct.app_label, ct.model, p.codename FROM auth_group_permissions gp JOIN auth_permission p ON p.id = gp.permission_id JOIN django_content_type ct ON ct.id = p.content_type_id) TO '/tmp/group_permissions.csv' WITH (FORMAT csv)
      \copy (SELECT up.user_id, ct.app_label, ct.model, p.codename FROM accounts_user_user_permissions up JOIN auth_permission p ON p.id = up.permission_id JOIN django_content_type ct ON ct.id = p.content_type_id) TO '/tmp/user_permissions.csv' WITH (FORMAT csv)
      SQL

   Then insert them with the new permission ids:

   .. code-block:: shell

      docker compose exec -T db psql -v ON_ERROR_STOP=1 -U rola -d rola <<'SQL'
      BEGIN;
      CREATE TEMPORARY TABLE old_group_permission (group_id bigint, app_label text, model text, codename text);
      CREATE TEMPORARY TABLE old_user_permission (user_id bigint, app_label text, model text, codename text);
      \copy old_group_permission FROM '/tmp/group_permissions.csv' WITH (FORMAT csv)
      \copy old_user_permission FROM '/tmp/user_permissions.csv' WITH (FORMAT csv)
      CREATE TEMPORARY VIEW permission_key AS
          SELECT p.id, ct.app_label, ct.model, p.codename
          FROM auth_permission p JOIN django_content_type ct ON ct.id = p.content_type_id;
      INSERT INTO auth_group_permissions (group_id, permission_id)
          SELECT o.group_id, k.id FROM old_group_permission o JOIN permission_key k USING (app_label, model, codename);
      INSERT INTO accounts_user_user_permissions (user_id, permission_id)
          SELECT o.user_id, k.id FROM old_user_permission o JOIN permission_key k USING (app_label, model, codename);
      SELECT 'group' AS kind, group_id AS id, app_label, model, codename FROM old_group_permission
          WHERE (app_label, model, codename) NOT IN (SELECT app_label, model, codename FROM permission_key)
      UNION ALL
      SELECT 'user', user_id, app_label, model, codename FROM old_user_permission
          WHERE (app_label, model, codename) NOT IN (SELECT app_label, model, codename FROM permission_key);
      COMMIT;
      SQL

   The last query lists the permissions that have no counterpart in the new
   schema. Permissions of removed models, such as the backup feature's, are
   expected there, with their old app label; anything else needs a look
   before going on.

#. Reset every sequence past the copied keys, so that new rows do not collide
   with them:

   .. code-block:: shell

      docker compose run --rm --no-deps -T migrate \
          python manage.py sqlsequencereset auth admin contenttypes accounts contests entries payments judging \
          | docker compose exec -T db psql -v ON_ERROR_STOP=1 -U rola -d rola

#. If the photographs were on disk, store them in the new stack's media
   storage: the media bucket with ``ROLA_USE_S3`` on, the ``media`` volume
   otherwise. The command stores each file of the archive under its path,
   skips a file that is already stored with the same size, so that it can
   run again after a failure, and stops at one stored with another size. It
   prints how many files it stored and skipped. In the bucket, a file
   appears only once it is complete. In the volume, a run that failed while
   writing a file leaves part of it, and the next run stops there: remove
   that file with ``docker compose run --rm --no-deps migrate rm
   /storage/media/<name>`` and run the command again.

   The command reads the archive as uid 1000, the backend's user. An
   archive that the Docker variant made on this server belongs to root and
   is readable already. If you own the archive, let that user read it;
   other accounts still cannot, because they cannot enter the transfer
   directory:

   .. code-block:: shell

      chmod a+r "$TRANSFER/rola-media.tar"

   Then store the files:

   .. code-block:: shell

      docker compose run --rm --no-deps -T -v "$TRANSFER/rola-media.tar":/tmp/rola-media.tar:ro \
          migrate python manage.py shell -c "
      import tarfile
      from django.core.files.storage import default_storage
      stored = skipped = 0
      with tarfile.open('/tmp/rola-media.tar') as archive:
          for member in archive:
              if not member.isfile():
                  continue
              name = member.name.removeprefix('./')
              if default_storage.exists(name):
                  if default_storage.size(name) == member.size:
                      skipped += 1
                      continue
                  raise SystemExit(f'{name} is already stored with another size')
              saved = default_storage.save(name, archive.extractfile(member))
              assert saved == name, (name, saved)
              stored += 1
      print('stored', stored, 'skipped', skipped)
      "

#. Strip the identifying metadata from the copied photographs and their
   thumbnails, as the new stack does for every upload (see "Uploads" in
   :doc:`deployment`); the old thumbnails carry the comment of their
   photograph. The command rewrites each photograph and thumbnail in the new
   stack's media storage under its name. Only the copies change: the old
   buckets or media directory keep the originals, so a rollback finds them
   unchanged. It skips images that have no such metadata, so it can run
   again after a failure. It names each file that is not a valid JPEG
   photograph and leaves it, with its metadata, as it is, and names each
   image that an upload row references but the media storage does not hold.
   Then it prints how many images it rewrote and skipped, how many files are
   not valid JPEG photographs and how many are not in storage. Copy an image
   that is not in storage from the old storage, if it is there, and run the
   command again:

   .. code-block:: shell

      docker compose run --rm --no-deps -T migrate python manage.py stripphotometadata

Verify and switch
=================

#. Compare the row counts of every table in the renamed scratch copy and the
   new database:

   .. code-block:: shell

      COUNTS="SELECT table_name, (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I', table_name), false, true, '')))[1]::text::int FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name"
      docker compose exec -T db psql -U rola -d rola_old -At -c "$COUNTS" > "$TRANSFER/counts-old.txt"
      docker compose exec -T db psql -U rola -d rola -At -c "$COUNTS" > "$TRANSFER/counts-new.txt"
      diff <(grep -E "^($COPIED)[|]" "$TRANSFER/counts-old.txt") <(grep -E "^($COPIED)[|]" "$TRANSFER/counts-new.txt")
      grep -vE "^($COPIED)[|]" "$TRANSFER/counts-old.txt" "$TRANSFER/counts-new.txt"

   The ``<(...)`` syntax needs bash or zsh. The ``diff`` compares the copied
   tables. It must print nothing and exit with status 0; if it prints a
   table, that table's row counts differ, so find the cause before going on.
   The ``grep`` lists the other tables from both databases.

   Only the tables that are not copied may differ: ``django_admin_log``,
   ``django_migrations``, ``django_session`` and ``accounts_token``, the
   new ``rola_cache``, and ``backup_filebackup`` if the old database has
   it. ``auth_permission`` and ``django_content_type`` may differ by the
   permissions and models that no longer exist, and the two permission
   tables by the rows that the remapping listed.

#. Delete the postal addresses that no account uses. The previous deployment
   kept an account's address when the account was deleted, and nothing in the
   application can show or delete such an address any more; the new stack
   deletes it with the account:

   .. code-block:: shell

      docker compose exec -T db psql -U rola -d rola -c \
          "DELETE FROM accounts_location l WHERE NOT EXISTS (SELECT 1 FROM accounts_user u WHERE u.location_id = l.id)"

   psql prints the number of deleted addresses as ``DELETE <n>``. From here
   on, ``accounts_location`` holds that many rows fewer than in the old
   database, so a repeated count comparison prints that table.

#. If the old deployment runs on the same server and still publishes port
   8080, stop it completely. Then start the new stack:

   .. code-block:: shell

      docker compose up -d --wait

#. Point the TLS terminator at ``127.0.0.1:8080``. Log in with an existing
   account, register a new one (this fails if a sequence was not reset), open
   a contest with photographs, and open the Django admin with a staff account.
   With a superuser account, open the contest with the most photographs there
   and download it with its Download button. If the download does not
   complete, contests of that size need ``manage.py exportcontest`` instead
   (see "Contest downloads" in :doc:`deployment`).
#. Remove the scratch database and the copies of the old data. Run
   ``rm -rf "$TRANSFER"`` on every other machine that has a transfer
   directory, too. ``-f`` removes an archive that the Docker variant made,
   which belongs to root, without asking:

   .. code-block:: shell

      docker compose exec -T db sh -c "dropdb -U rola --if-exists rola_old && rm -f /tmp/rola-old.dump /tmp/rola-renamed.dump /tmp/rola-renamed.list /tmp/restore.list /tmp/group_permissions.csv /tmp/user_permissions.csv"
      rm -rf "$TRANSFER"

   Run both commands also when you abandon a run, at whatever step: they
   skip what the run had not yet made. A later attempt starts from the reset
   in "Prepare the new stack" and a new dump.

After the switch
================

Activation and password-reset links that the previous deployment sent do not
work on the new stack, whatever ``ROLA_SECRET_KEY`` is: the previous
deployment ran Django 3.0, which signed them with SHA-1, and Django 6.1 checks
SHA-256 signatures. An active account with an old reset link gets "Bad token."
and has to request a new link.

No new activation links are sent. Someone who registered before the freeze
and has not activated the account can register again with the same address:
the email they get links to a password reset, and setting a new password
activates the account. If such a person asks for a new activation link
instead, send one, filling in the address. The command fails with
``DoesNotExist`` if no inactive account has that address, and reports a
message that the mail server refused as ``Unable to send account email``:

.. code-block:: shell

   docker compose exec -T backend python manage.py shell -c "
   from rola.accounts.models import User
   from rola.accounts.utils.signing import send_activation_email
   send_activation_email(User.objects.get(email__iexact='<address>', is_active=False))
   "

The previous deployment kept the stored photographs of deleted submissions,
and the uploads that a submission replaced or never received, with their
photographs. ``deleteorphanphotos`` (see "Maintenance" in :doc:`deployment`)
deletes them from the new stack. Copying the photographs gave every stored
file a new modification time, so only a run at least a day after the copy
deletes the photographs of deleted submissions; an earlier run deletes only
the uploads and their photographs. The old database and the old buckets or
media directory keep them, so a rollback still finds them.

Rollback
========

Rolling back means stopping the new stack, pointing the TLS terminator back
at the old deployment and restarting its web server from the old deployment's
directory. The old buckets or media directory have not changed since the
freeze, and the old database only by the fixes that the checks called for: a
changed email address, merged duplicate judges, removed duplicate ratings,
corrected scores, a club or school that a contest no longer requires or now
shows. The old deployment therefore finds every photograph it had, and its
results show the corrected totals. Everything written to the
new stack in the meantime is lost.
