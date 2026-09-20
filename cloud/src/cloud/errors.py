"""Safe Cloud service error types and validation helpers."""

from pydantic import ValidationError


class CloudStartupError(Exception):
    """Raised when startup material is unusable."""


class DatabaseError(Exception):
    """Raised when PostgreSQL cannot complete a persistence operation."""


class EnvelopeError(Exception):
    """Raised for malformed or cryptographically invalid envelopes."""


class ObservationValidationError(Exception):
    """Raised when decrypted plaintext is not a valid observation."""


def validation_codes(error: ValidationError) -> list[str]:
    """Return safe validation error codes without rejected input values."""
    return sorted({item["type"] for item in error.errors(include_input=False)})
