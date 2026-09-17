Unreleased
==========

* Upgrade to Python 3.12–3.14, Django 6.1, DRF 3.18, django-filter 26,
  Pillow 12, current Channels/boto3, and psycopg 3.
* Move packaging to pyproject.toml and replace pkg_resources metadata access.
* Repair the standalone test host while preserving Rola's external user/email
  models and historical migration dependency.
* Fix author listing, submission validation and permissions, transactional batch
  creation, filtering, export, rating validation, and PostgreSQL judging order.
* Modernize thumbnail generation, including historical migration 0017.
* Add workflow, media, migration, payment, judging, and Redis worker tests.
* Modernize CI, documentation, linters, and local PostgreSQL/Redis services.

See upgrading.rst for host configuration and deployment requirements.
