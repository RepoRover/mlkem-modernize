"""Device AES-GCM envelope creation."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from device.errors import DeviceError
from device.models import DeviceEnvelope, Observation


def device_aad(
    device_id: str, key_id: str, observation_id: str, version: int = 1
) -> bytes:
    """Build Device-envelope additional authenticated data."""
    return b"\0".join(
        part.encode()
        for part in (
            "device-envelope",
            str(version),
            device_id,
            key_id,
            observation_id,
        )
    )


def encrypt_observation(
    observation: Observation, key_id: str, key: bytes
) -> DeviceEnvelope:
    """Encrypt one observation into a fresh Device envelope."""
    if len(key) != 32:
        raise DeviceError("Device AES key must be exactly 32 bytes")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        observation.model_dump_json().encode(),
        device_aad(observation.device_id, key_id, observation.observation_id),
    )
    if len(ciphertext) > 16 * 1024:
        raise DeviceError("encrypted observation exceeds protocol limit")
    return DeviceEnvelope(
        device_id=observation.device_id,
        key_id=key_id,
        observation_id=observation.observation_id,
        nonce=base64.b64encode(nonce).decode("ascii"),
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
    )
