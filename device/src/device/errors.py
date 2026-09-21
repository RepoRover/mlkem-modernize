"""Device errors and safe validation diagnostics."""

from pydantic import ValidationError


class DeviceError(Exception):
    """Expected fatal Device error safe to report without rejected values."""


def validation_codes(error: ValidationError) -> str:
    """Return bounded library error codes, never attacker-controlled locations."""
    return ",".join(
        sorted({item["type"] for item in error.errors(include_input=False)})
    )[:512]
