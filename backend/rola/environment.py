"""Read typed application environment variables."""

import os


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
