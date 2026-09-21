"""Key establishment and record protection for both cipher suites.

Importing this package never requires ML-KEM. The hybrid suite raises
:class:`CapabilityError` only when it is actually used, so a node with a
pre-quantum crypto backend can still import the code, report its capabilities,
and speak the legacy suite.
"""

from cryptosuite.capabilities import (
    MLKEM_AVAILABLE,
    CapabilityError,
    CapabilityReport,
    mlkem_module,
    probe,
    supported_suites,
)
from cryptosuite.hybrid import (
    HybridClient,
    HybridServer,
    Offer,
    generate_identity_key,
    load_identity_private,
    load_identity_public,
    serialize_identity_private,
    serialize_identity_public,
)
from cryptosuite.keystore import load_or_create_identity, load_or_create_rsa
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
    "HybridClient",
    "HybridServer",
    "LegacyClient",
    "LegacyServer",
    "Offer",
    "RecordSession",
    "generate_identity_key",
    "generate_private_key",
    "load_identity_private",
    "load_identity_public",
    "load_or_create_identity",
    "load_or_create_rsa",
    "load_private_key",
    "load_public_key",
    "mlkem_module",
    "new_session_id",
    "probe",
    "recover_session_key",
    "serialize_identity_private",
    "serialize_identity_public",
    "serialize_private_key",
    "serialize_public_key",
    "supported_suites",
]
