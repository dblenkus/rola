==========================
Upgrading an existing host
==========================

Supported stack
===============

Rolca now targets Python 3.12–3.14, Django 6.1, Django REST framework 3.18,
django-filter 26, Pillow 12, Channels 4.3, and psycopg 3. PostgreSQL 15 or newer is
required by Django 6.1. CI and local Compose use PostgreSQL 18.6 and Redis 8.10.1.
The ``psycopg[binary]`` dependency replaces ``psycopg2-binary``.

This repository supplies reusable Django apps. The companion Rola host provides
``drf_user.User`` and ``drf_user.Email``. The unrelated PyPI package named
``drf-user`` is not a replacement. Keep the real host app and its migrations,
including ``drf_user.0004_email``, installed. Core migration 0010 continues to
reference that historical node, and the model retains its foreign key to
``drf_user.Email``. No user table, email template, or primary-key conversion is
introduced by this upgrade.

The host must set ``AUTH_USER_MODEL``, include its user app and Rolca apps in
``INSTALLED_APPS``, and provide the optional ``user.location.country`` relationship
used in result serialization. Review and upgrade the host's authentication,
token, email, storage, and middleware dependencies separately.

Settings and integration
========================

Set ``USE_TZ`` explicitly and test contest dates around timezone and daylight
saving boundaries. Rolca app configurations retain ``AutoField`` to preserve
existing primary keys despite Django's newer default.

Configure ``ROLCA_MAX_UPLOAD_SIZE`` in bytes and
``ROLCA_MAX_UPLOAD_RESOLUTION`` in pixels for the image validator. The previous
test-only names ``ROLCA_MAX_SIZE`` and ``ROLCA_MAX_LONG_EDGE`` are not read by the
validator.

Configure ``BACKUP_AWS_BUCKET_NAME``, ``BACKUP_AWS_ACCESS_KEY_ID``, and
``BACKUP_AWS_SECRET_ACCESS_KEY``, plus a Redis-backed ``CHANNEL_LAYERS`` setting
for background workers. Construct consumers with ``BackupConsumer.as_asgi()``
and set the host's own ``ASGI_APPLICATION``. ``tests.routing`` is an example,
not a production ASGI entry point.

Django 6.1 deprecates ``EMAIL_BACKEND`` in favor of ``MAILERS``. Configure the
host's mailer and verify confirmation messages in staging. Preserve any custom
email-template behavior in the host app. The built-in logout view requires POST;
check the consuming frontend's logout flow and CSRF handling.

When constructing a custom DRF router from ``route_lists``, explicitly give each
route a unique basename, for example::

    for routes in route_lists:
        for prefix, viewset in routes:
            router.register(prefix, viewset, basename=prefix.replace('/', '-'))

This avoids collisions between core, judge, and results viewsets under current
DRF. Rolca's router uses these names; URL paths and payload shapes are preserved.
Custom reverse lookups for judge/results routes must use their new distinct names.

Behavior fixes to verify with clients
=====================================

* Filters now use ``filterset_class``; query parameters previously ignored by
  django-filter now take effect.
* Author listing is scoped correctly. Submission writes require ownership and
  are blocked after publication. Related author/file IDs must belong to the
  requester. Files cannot be reused across submissions.
* Single and batch submission requests create one submission set atomically.
  Empty batches, mixed contests/authors, and duplicate files return validation
  errors. A failed database write does not leave a partial submission set.
* Confirmation mail is dispatched after a successful transaction commit.
* Submission updates keep their author and contest, preserving set membership.
* Rating updates cannot move a score to another submission, and score writes
  require an active judge for the contest.
* Contest exports require the organizer or a superuser, include all submission
  files, and read through Django storage rather than assuming local file paths.
* The PostgreSQL expression used for stable judging order explicitly casts its
  integer input to text.

Data and rollout rehearsal
==========================

Back up the database and media, record migration state, and restore both into an
isolated staging environment. Run system checks and ``migrate --plan`` before
applying migrations. Verify counts and relations for users, authors, contests,
submissions, files, payments, ratings, rewards, and email templates.

Migration 0017 retains its identity and image-regeneration behavior but uses
Pillow's supported resampling API. Test an upgrade from before this migration
with actual media if that represents the deployed version. The automated test
runs its image loop using historical models and a real stored image; it does
not replace a rehearsal using the host's complete migration history.

A PostgreSQL major upgrade needs ``pg_upgrade`` or a dump/restore; simply changing
the image tag on an existing data volume is insufficient. Schedule it separately
from the application cutover. Confirm ``pgcrypto`` is available for the historical
rating migration.

Verify entrant, organizer, judge, and anonymous-user workflows, login/logout,
image upload, results publication, export, and a real S3 backup and restore.
Automated tests use a fake S3 client and real Redis/PostgreSQL services; they do
not validate production AWS credentials or bucket policies.

Retain the previous application artifact and a tested database/media restore.
Historical data migrations do not all have reverse functions. Account for new
writes before attempting rollback; a reverse ``migrate`` command alone is not a
complete rollback procedure.
