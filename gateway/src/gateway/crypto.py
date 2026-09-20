"""Device decryption and Cloud ML-KEM envelope creation."""

import base64
import binascii
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import ValidationError

from gateway.errors import (
    DeviceAuthenticationError,
    EnvelopeError,
    GatewayStartupError,
    ObservationValidationError,
)
from gateway.models import (
    MAX_CIPHERTEXT_BYTES,
    CloudEnvelope,
    DeviceEnvelope,
    Observation,
)

MLKEM_PUBLIC_KEY_BYTES = 1184
MLKEM_CIPHERTEXT_BYTES = 1088


def _joined(parts: tuple[str, ...]) -> bytes:
    """Encode protocol fields with the specified zero-byte separator."""
    return b"\0".join(part.encode("utf-8") for part in parts)


def device_aad(envelope: DeviceEnvelope) -> bytes:
    """Build Device-envelope additional authenticated data."""
    return _joined(
        (
            "device-envelope",
            str(envelope.version),
            envelope.device_id,
            envelope.key_id,
            envelope.observation_id,
        )
    )


def _cloud_aad_values(gateway_id: str, kem_key_id: str, observation_id: str) -> bytes:
    """Build Cloud AAD from the authenticated metadata values."""
    return _joined(
        (
            "cloud-envelope",
            "1",
            gateway_id,
            "ML-KEM-768",
            kem_key_id,
            observation_id,
        )
    )


def cloud_aad(envelope: CloudEnvelope) -> bytes:
    """Build Cloud-envelope additional authenticated data."""
    return _cloud_aad_values(
        envelope.gateway_id, envelope.kem_key_id, envelope.observation_id
    )


def cloud_hkdf_info(kem_key_id: str) -> bytes:
    """Build the domain-separated Cloud key-derivation context."""
    return _joined(("mlkem-modernize", "cloud-envelope", "1", kem_key_id))


def _decode_base64(value: str, field: str) -> bytes:
    """Strictly decode one padded RFC 4648 base64 field."""
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise EnvelopeError(f"{field} is not valid base64") from error


def load_mlkem_public_key(path: Path) -> MLKEM768PublicKey:
    """Load and validate a raw pinned ML-KEM-768 public key."""
    try:
        encoded = path.read_bytes()
    except OSError as error:
        raise GatewayStartupError("ML-KEM public key could not be read") from error
    if len(encoded) != MLKEM_PUBLIC_KEY_BYTES:
        raise GatewayStartupError("ML-KEM public key has an invalid length")
    try:
        return MLKEM768PublicKey.from_public_bytes(encoded)
    except (ValueError, UnsupportedAlgorithm) as error:
        raise GatewayStartupError(
            "ML-KEM-768 is unavailable or key is invalid"
        ) from error


def decrypt_device_envelope(
    envelope: DeviceEnvelope,
    expected_device_id: str,
    expected_key_id: str,
    device_key: bytes,
) -> Observation:
    """Authenticate, decrypt, and validate one Device envelope."""
    if envelope.device_id != expected_device_id or envelope.key_id != expected_key_id:
        raise DeviceAuthenticationError("unknown Device or key identity")

    nonce = _decode_base64(envelope.nonce, "nonce")
    ciphertext = _decode_base64(envelope.ciphertext, "ciphertext")
    if len(nonce) != 12 or not 16 <= len(ciphertext) <= MAX_CIPHERTEXT_BYTES:
        raise EnvelopeError("Device envelope field length is invalid")

    try:
        plaintext = AESGCM(device_key).decrypt(nonce, ciphertext, device_aad(envelope))
    except InvalidTag as error:
        raise DeviceAuthenticationError("Device authentication failed") from error

    try:
        observation = Observation.model_validate_json(plaintext)
    except ValidationError as error:
        raise ObservationValidationError("observation validation failed") from error
    if (
        observation.device_id != envelope.device_id
        or observation.observation_id != envelope.observation_id
    ):
        raise ObservationValidationError("observation identity mismatch")
    return observation


def encrypt_cloud_envelope(
    observation: Observation,
    gateway_id: str,
    kem_key_id: str,
    public_key: MLKEM768PublicKey,
) -> CloudEnvelope:
    """Create a fresh ML-KEM/AES-GCM Cloud envelope."""
    shared_secret, kem_ciphertext = public_key.encapsulate()
    if len(shared_secret) != 32 or len(kem_ciphertext) != MLKEM_CIPHERTEXT_BYTES:
        raise RuntimeError("ML-KEM-768 backend returned invalid output lengths")
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=cloud_hkdf_info(kem_key_id),
    ).derive(shared_secret)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        observation.model_dump_json().encode("utf-8"),
        _cloud_aad_values(gateway_id, kem_key_id, observation.observation_id),
    )
    if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise RuntimeError("encrypted observation exceeds protocol limit")
    return CloudEnvelope(
        gateway_id=gateway_id,
        kem_key_id=kem_key_id,
        observation_id=observation.observation_id,
        kem_ciphertext=base64.b64encode(kem_ciphertext).decode("ascii"),
        nonce=base64.b64encode(nonce).decode("ascii"),
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
    )
