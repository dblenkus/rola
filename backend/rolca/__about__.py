"""Central place for package metadata."""

from importlib.metadata import PackageNotFoundError, version

__title__ = "rolca"
__summary__ = "Open source platform for uploading photos"
__url__ = "https://github.com/dblenkus/rolca"

try:
    __version__ = version(__title__)
except PackageNotFoundError:
    __version__ = "0+unknown"

__author__ = "Domen Blenkuš"
__email__ = "domen@blenkus.com"

__license__ = "Apache License (2.0)"
__copyright__ = "2014-2016, " + __author__

__all__ = (
    "__title__",
    "__summary__",
    "__url__",
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__copyright__",
)
