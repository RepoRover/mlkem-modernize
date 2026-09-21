"""Classical (pre-quantum) crypto primitives for the legacy baseline.

Everything here is a thin wrapper over `cryptography`. No primitive is
implemented by hand. This module is the ONLY place that touches key material.

Suite (baseline / "before" state):
  - key agreement : ECDH over NIST P-256
  - signatures    : ECDSA over NIST P-256 with SHA-256
  - KDF           : HKDF-SHA256
  - AEAD          : AES-256-GCM

All of the above except AES-GCM is broken by a cryptographically relevant
quantum computer. That is the point of this file: it is the thing we migrate.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .wire import counter_bytes

CURVE = ec.SECP256R1()
SHARED_SECRET_LEN = 32
SESSION_KEY_LEN = 32
NONCE_PREFIX_LEN = 4
NONCE_LEN = 12  # 4-byte per-session prefix + 8-byte counter
HANDSHAKE_NONCE_LEN = 16
SESSION_ID_LEN = 16


# --------------------------------------------------------------------------
# key handling
# --------------------------------------------------------------------------


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def private_key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(path: str | os.PathLike) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError(f"{path} is not an EC private key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"{path} is not on P-256")
    return key


def load_public_key(path: str | os.PathLike) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError(f"{path} is not an EC public key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"{path} is not on P-256")
    return key


def public_key_to_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    """X9.62 uncompressed point (65 bytes for P-256)."""
    return key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def public_key_from_bytes(raw: bytes) -> ec.EllipticCurvePublicKey:
    """Parse an X9.62 uncompressed point.

    `from_encoded_point` rejects points that are not on the curve, which is the
    check that stops an invalid-curve attack against our static ECDH keys.
    """
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, raw)


# --------------------------------------------------------------------------
# agreement, derivation, signatures
# --------------------------------------------------------------------------


def ecdh(private_key: ec.EllipticCurvePrivateKey, peer_public: ec.EllipticCurvePublicKey) -> bytes:
    """Raw ECDH; returns the 32-byte x-coordinate. Never use this directly as a key."""
    return private_key.exchange(ec.ECDH(), peer_public)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = SESSION_KEY_LEN) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """ECDSA-P256-SHA256, DER encoded."""
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(public_key: ec.EllipticCurvePublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


# --------------------------------------------------------------------------
# AEAD framing
# --------------------------------------------------------------------------


class NonceReuse(Exception):
    """Raised rather than ever emitting a repeated (key, nonce) pair."""


class ReplayRejected(Exception):
    """Receiver saw a sequence number it has already accepted (or an older one)."""


def _nonce(prefix: bytes, seq: int) -> bytes:
    if len(prefix) != NONCE_PREFIX_LEN:
        raise ValueError("bad nonce prefix length")
    return prefix + counter_bytes(seq)


def _aad(session_id: bytes, seq: int) -> bytes:
    return session_id + counter_bytes(seq)


class AeadSender:
    """Encrypts a strictly increasing sequence of messages under one session key.

    Nonce = 4-byte session-unique prefix || 8-byte counter. Because the prefix is
    fixed per session and the counter never repeats within a session, the
    (key, nonce) pair is unique by construction -- which is the property
    AES-GCM needs and the one it fails catastrophically without.
    """

    def __init__(self, key: bytes, session_id: bytes, nonce_prefix: bytes) -> None:
        if len(key) != SESSION_KEY_LEN:
            raise ValueError("session key must be 32 bytes")
        self._aead = AESGCM(key)
        self._session_id = session_id
        self._prefix = nonce_prefix
        self._next_seq = 0

    @property
    def next_seq(self) -> int:
        return self._next_seq

    def encrypt(self, plaintext: bytes) -> tuple[int, bytes, bytes]:
        """Returns (seq, nonce, ciphertext-with-tag)."""
        seq = self._next_seq
        nonce = _nonce(self._prefix, seq)
        ct = self._aead.encrypt(nonce, plaintext, _aad(self._session_id, seq))
        self._next_seq += 1
        return seq, nonce, ct


class AeadReceiver:
    """Decrypts messages from an AeadSender, rejecting replays and reordering.

    We require a strictly increasing sequence rather than a sliding window. On a
    reliable transport (HTTP) that is adequate and much easier to reason about;
    the cost is that a single dropped message stalls the session until rekey.
    """

    def __init__(self, key: bytes, session_id: bytes, nonce_prefix: bytes) -> None:
        if len(key) != SESSION_KEY_LEN:
            raise ValueError("session key must be 32 bytes")
        self._aead = AESGCM(key)
        self._session_id = session_id
        self._prefix = nonce_prefix
        self._highest_seq: int | None = None

    @property
    def highest_seq(self) -> int | None:
        return self._highest_seq

    def decrypt(self, seq: int, nonce: bytes, ciphertext: bytes) -> bytes:
        if self._highest_seq is not None and seq <= self._highest_seq:
            raise ReplayRejected(f"seq {seq} already seen (highest {self._highest_seq})")

        expected_nonce = _nonce(self._prefix, seq)
        if nonce != expected_nonce:
            # The nonce is fully determined by the session and the counter, so a
            # mismatch means the peer is not following the protocol.
            raise ReplayRejected("nonce does not match session prefix and counter")

        # Raises InvalidTag on tampering; callers translate that to a rejection.
        plaintext = self._aead.decrypt(nonce, ciphertext, _aad(self._session_id, seq))
        self._highest_seq = seq
        return plaintext
