"""Device errors and safe validation diagnostics."""

from pydantic import ValidationError


class DeviceError(Exception):
    """Expected fatal Device error safe to report without rejected values."""


def validation_codes(error: ValidationError) -> str:
    """Return field names and error codes without rejected input values."""
    return ",".join(
        f"{'.'.join(map(str, item['loc']))}:{item['type']}" for item in error.errors()
    )
