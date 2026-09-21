"""Key establishment and record protection for both cipher suites.

Only the legacy suite exists at this baseline. :mod:`cryptosuite.capabilities`
already reports whether the installed crypto backend could support ML-KEM,
which is what the migration will build on.
"""

from cryptosuite.capabilities import (
    MLKEM_AVAILABLE,
    CapabilityError,
    CapabilityReport,
    mlkem_module,
    probe,
    supported_suites,
)
from cryptosuite.keystore import load_or_create_rsa
from cryptosuite.legacy import (
    LegacyClient,
    LegacyServer,
    generate_private_key,
    load_private_key,
    load_public_key,
    new_session_id,
    recover_session_key,
    serialize_private_key,
    serialize_public_key,
)
from cryptosuite.record import KEY_LENGTH, AuthenticationError, RecordSession

__all__ = [
    "KEY_LENGTH",
    "MLKEM_AVAILABLE",
    "AuthenticationError",
    "CapabilityError",
    "CapabilityReport",
    "LegacyClient",
    "LegacyServer",
    "RecordSession",
    "generate_private_key",
    "load_or_create_rsa",
    "load_private_key",
    "load_public_key",
    "mlkem_module",
    "new_session_id",
    "probe",
    "recover_session_key",
    "serialize_private_key",
    "serialize_public_key",
    "supported_suites",
]
