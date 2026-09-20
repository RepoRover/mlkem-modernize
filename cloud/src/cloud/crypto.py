"""ML-KEM key loading and Cloud-envelope decryption."""

import base64
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import ValidationError

from cloud.errors import CloudStartupError, EnvelopeError, ObservationValidationError
from cloud.models import MAX_CIPHERTEXT_BYTES, CloudEnvelope, Observation

MLKEM_CIPHERTEXT_BYTES = 1088


def _joined(parts: tuple[str, ...]) -> bytes:
    return b"\0".join(part.encode("utf-8") for part in parts)


def cloud_aad(envelope: CloudEnvelope) -> bytes:
    """Build authenticated Cloud-envelope metadata."""
    return _joined(
        (
            "cloud-envelope",
            "1",
            envelope.gateway_id,
            envelope.kem,
            envelope.kem_key_id,
            envelope.observation_id,
        )
    )


def cloud_hkdf_info(key_id: str) -> bytes:
    """Build the domain-separated key derivation context."""
    return _joined(("mlkem-modernize", "cloud-envelope", "1", key_id))


def _decode(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise EnvelopeError(f"{field} is not valid base64") from error


def load_private_keys(directory: Path) -> dict[str, MLKEM768PrivateKey]:
    """Load every PEM ML-KEM-768 private key named ``<key-id>.pem``."""
    keys: dict[str, MLKEM768PrivateKey] = {}
    try:
        paths = sorted(directory.glob("*.pem"))
    except OSError as error:
        raise CloudStartupError("ML-KEM key directory could not be read") from error
    for path in paths:
        key_id = path.stem
        if not key_id or any(not (char.isalnum() or char in "._:-") for char in key_id):
            raise CloudStartupError("ML-KEM private key filename is invalid")
        try:
            loaded = serialization.load_pem_private_key(
                path.read_bytes(), password=None
            )
        except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as error:
            raise CloudStartupError("ML-KEM private key could not be loaded") from error
        if not isinstance(loaded, MLKEM768PrivateKey):
            raise CloudStartupError("private key is not ML-KEM-768")
        keys[key_id] = loaded
    if not keys:
        raise CloudStartupError("no ML-KEM-768 private keys were loaded")
    return keys


def decrypt_cloud_envelope(
    envelope: CloudEnvelope, private_key: MLKEM768PrivateKey
) -> Observation:
    """Decapsulate, decrypt, and validate one Cloud envelope."""
    kem_ciphertext = _decode(envelope.kem_ciphertext, "kem_ciphertext")
    nonce = _decode(envelope.nonce, "nonce")
    ciphertext = _decode(envelope.ciphertext, "ciphertext")
    if (
        len(kem_ciphertext) != MLKEM_CIPHERTEXT_BYTES
        or len(nonce) != 12
        or not 16 <= len(ciphertext) <= MAX_CIPHERTEXT_BYTES
    ):
        raise EnvelopeError("Cloud envelope field length is invalid")
    try:
        secret = private_key.decapsulate(kem_ciphertext)
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=cloud_hkdf_info(envelope.kem_key_id),
        ).derive(secret)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, cloud_aad(envelope))
    except (InvalidTag, ValueError) as error:
        raise EnvelopeError("Cloud envelope authentication failed") from error
    try:
        observation = Observation.model_validate_json(plaintext)
    except ValidationError as error:
        raise ObservationValidationError("observation validation failed") from error
    if observation.observation_id != envelope.observation_id:
        raise ObservationValidationError("observation identity mismatch")
    return observation
