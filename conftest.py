"""Fixtures for integration tests."""

import pytest


@pytest.fixture(autouse=True)
def media_root(settings, tmp_path):
    """Keep media written by tests outside the source tree."""
    settings.MEDIA_ROOT = tmp_path
