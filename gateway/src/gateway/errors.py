"""Gateway exceptions and safe validation diagnostics."""

from pydantic import ValidationError


class GatewayError(Exception):
    """Base class for expected Gateway failures safe to classify."""


class GatewayStartupError(GatewayError):
    """Gateway configuration or key material could not be loaded."""


class EnvelopeError(GatewayError):
    """A Device envelope is malformed."""


class DeviceAuthenticationError(GatewayError):
    """A Device identity, key identity, or authentication tag is invalid."""


class ObservationValidationError(GatewayError):
    """Decrypted Device plaintext is not a valid observation."""


class TransientCloudError(GatewayError):
    """Cloud delivery failed for a retryable reason."""


class PermanentCloudError(GatewayError):
    """Cloud rejected the Gateway configuration or protocol."""


def validation_codes(error: ValidationError) -> str:
    """Return field names and error codes without rejected input values."""
    return ",".join(
        f"{'.'.join(map(str, item['loc']))}:{item['type']}" for item in error.errors()
    )
