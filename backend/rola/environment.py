"""Read typed application environment variables."""

import os
from urllib.parse import urlsplit


def absolute_url(name: str) -> str:
    """Read a required absolute http or https URL that paths can be appended to.

    :raises KeyError: If the variable is unset.
    :raises ValueError: If the value is not an absolute http or https URL, or
        has surrounding whitespace, credentials, a query or a fragment.
    """
    value = os.environ[name]
    url = urlsplit(value)
    if (
        url.scheme not in {"http", "https"}
        or not url.hostname
        or value != value.strip()
        or "@" in url.netloc
        or "?" in value
        or "#" in value
    ):
        raise ValueError(
            f"{name} must be an absolute http or https URL without "
            "credentials, a query or a fragment."
        )
    return value


def boolean(name: str) -> bool:
    """Read a boolean that is false when unset.

    :raises ValueError: If the variable is set to an empty or unrecognized value.
    """
    value = os.environ.get(name)
    if value is None:
        return False
    if value.lower() in {"true", "1", "yes", "on"}:
        return True
    if value.lower() in {"false", "0", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean.")


def comma_separated(name: str) -> list[str]:
    """Read the nonempty items of a comma-separated variable, empty when unset."""
    return [
        item.strip() for item in os.environ.get(name, "").split(",") if item.strip()
    ]
