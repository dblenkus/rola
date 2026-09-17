"""Sphinx configuration using the documented test host contract."""

import os
import sys
from pathlib import Path

import django

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
django.setup()

from rolca import __about__ as about

project = about.__title__
version = about.__version__
release = version
author = about.__author__
copyright = about.__copyright__
extensions = ['sphinx.ext.autodoc', 'sphinx.ext.intersphinx', 'sphinx.ext.viewcode']
source_suffix = {'.rst': 'restructuredtext'}
master_doc = 'index'
language = 'en'
exclude_patterns = ['_build', 'CHANGELOG.rst']
html_theme = 'sphinx_rtd_theme'
intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
    'django': (
        'https://docs.djangoproject.com/en/6.1/',
        'https://docs.djangoproject.com/en/6.1/objects.inv',
    ),
}
