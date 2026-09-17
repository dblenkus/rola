=====
Rolca
=====

|build| |coverage| |docs|

.. |build| image:: https://github.com/dblenkus/rolca/workflows/build/badge.svg?branch=master
    :target: https://github.com/dblenkus/rolca/actions?query=workflow%3Abuild
    :alt: Build Status

.. |coverage| image:: https://codecov.io/gh/dblenkus/rolca/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/dblenkus/rolca
    :alt: Coverage Status

.. |docs| image:: https://readthedocs.org/projects/rolca/badge/?version=latest
    :target: http://rolca.readthedocs.io/
    :alt: Documentation Status

Open source platform for organising photography contests.


Development and upgrades
========================

Requires Python 3.12–3.14 and Django 6.1. See ``docs/contributing.rst`` for
installation and tests, and ``docs/upgrading.rst`` for integration and migration
requirements. Rolca relies on the host application's ``drf_user`` models; the
unrelated PyPI package with that name is not a substitute.
