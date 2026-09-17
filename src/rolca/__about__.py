# -*- coding: utf-8 -*-
"""Central place for package metadata."""

from importlib.metadata import PackageNotFoundError, version

# NOTE: __title__ is used instead of simply __name__ since the latter
#       would interfere with a global variable __name__ denoting
#       object's name.
__title__ = 'rolca'
__summary__ = 'Open source platform for uploading photos'
__url__ = 'https://github.com/dblenkus/rolca'

try:
    __version__ = version(__title__)
except PackageNotFoundError:
    # Package is not (yet) installed.
    __version__ = '0+unknown'

__author__ = 'Domen Blenkuš'
__email__ = 'domen@blenkus.com'

__license__ = 'Apache License (2.0)'
__copyright__ = '2014-2016, ' + __author__

__all__ = (
    '__title__',
    '__summary__',
    '__url__',
    '__version__',
    '__author__',
    '__email__',
    '__license__',
    '__copyright__',
)
