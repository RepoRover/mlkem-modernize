"""Crypto primitives, classical and post-quantum.

Everything here is a thin wrapper over `cryptography`. No primitive is
implemented by hand. This module is the ONLY place that touches key material.

Classical (hop 1, and the hop 2 `classical-p256` fallback):
  - key agreement : ECDH over NIST P-256
  - signatures    : ECDSA over NIST P-256 with SHA-256

Post-quantum (hop 2 `hybrid-x25519-mlkem768`):
  - key agreement : X25519 ECDHE  +  ML-KEM-768 (FIPS 203)

Shared by both:
  - KDF           : HKDF-SHA256
  - AEAD          : AES-256-GCM

ECDH, X25519 and ECDSA all fall to Shor. ML-KEM does not, which is why the
hybrid combines it with X25519 rather than replacing X25519 outright: the
result is secure if EITHER component holds.

ML-KEM comes from `cryptography` >= 48 backed by OpenSSL >= 3.5. We pin the
exact version in requirements.txt because this module is the whole crypto
surface of the system.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
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

# X25519 (RFC 7748)
X25519_PUBLIC_LEN = 32
X25519_SHARED_LEN = 32

# ML-KEM-768 (FIPS 203). Sizes are fixed by the standard and asserted at import
# time below, so a library change that altered them fails loudly and early.
MLKEM768_EK_LEN = 1184  # encapsulation key ("public key")
MLKEM768_CT_LEN = 1088  # ciphertext
MLKEM768_SS_LEN = 32  # shared secret
MLKEM768_SEED_LEN = 64  # d||z seed; how cryptography serialises the private key


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
# X25519 (the classical half of the hybrid)
# --------------------------------------------------------------------------


def generate_x25519_private_key() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def x25519_public_bytes(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes_raw()


def x25519_public_from_bytes(raw: bytes) -> x25519.X25519PublicKey:
    """Parse a 32-byte X25519 public key.

    X25519 has no invalid-curve problem the way P-256 does -- every 32-byte
    string is a valid input -- so the only check is the length. Note that some
    inputs (low-order points) produce an all-zero shared secret; see
    `x25519_exchange`.
    """
    if len(raw) != X25519_PUBLIC_LEN:
        raise ValueError(f"X25519 public key must be {X25519_PUBLIC_LEN} bytes")
    return x25519.X25519PublicKey.from_public_bytes(raw)


def x25519_exchange(
    private_key: x25519.X25519PrivateKey, peer_public: x25519.X25519PublicKey
) -> bytes:
    """X25519 key agreement.

    `cryptography` raises on an all-zero output, which is the low-order-point
    case RFC 7748 section 6.1 tells implementations to reject. We let that
    propagate: the handshake must fail, not continue with a degenerate secret.
    """
    shared = private_key.exchange(peer_public)
    if len(shared) != X25519_SHARED_LEN:  # pragma: no cover - defensive
        raise ValueError("unexpected X25519 shared secret length")
    return shared


# --------------------------------------------------------------------------
# ML-KEM-768 (FIPS 203) -- the post-quantum half of the hybrid
# --------------------------------------------------------------------------


class InvalidEncapsulationKey(ValueError):
    """Peer sent an encapsulation key that is not a valid ML-KEM-768 key.

    Raised for both a wrong length and a failed FIPS 203 input check. We use our
    own message rather than the library's, because the library reports a modulus
    -check failure as "An ML-KEM-768 public key is 1184 bytes long", which is
    confusing when the input is in fact 1184 bytes.
    """


def generate_mlkem768_private_key() -> mlkem.MLKEM768PrivateKey:
    """Fresh ML-KEM-768 decapsulation key.

    Generated per handshake and discarded afterwards. Reusing it across
    sessions would forfeit forward secrecy on the post-quantum half.
    """
    return mlkem.MLKEM768PrivateKey.generate()


def mlkem768_encapsulation_key_bytes(private_key: mlkem.MLKEM768PrivateKey) -> bytes:
    return private_key.public_key().public_bytes_raw()


def mlkem768_encapsulation_key_from_bytes(raw: bytes) -> mlkem.MLKEM768PublicKey:
    """Parse and validate a peer's encapsulation key.

    FIPS 203 section 7.2 requires two input checks on `ek`: the length check, and the
    "modulus check" -- ByteDecode12 followed by ByteEncode12 must round-trip,
    which rejects any 12-bit coefficient >= q = 3329.

    Both are performed by the library and verified by our tests:
    an all-zero key is ACCEPTED (every coefficient is 0, a legal encoding),
    a key whose first coefficient is 3328 is ACCEPTED, and one whose first
    coefficient is 3329 is REJECTED. See tests/test_pqc.py.
    """
    if len(raw) != MLKEM768_EK_LEN:
        raise InvalidEncapsulationKey(
            f"encapsulation key must be {MLKEM768_EK_LEN} bytes, got {len(raw)}"
        )
    try:
        return mlkem.MLKEM768PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise InvalidEncapsulationKey("encapsulation key failed FIPS 203 input check") from exc


def mlkem768_encapsulate(public_key: mlkem.MLKEM768PublicKey) -> tuple[bytes, bytes]:
    """Encapsulate to a peer's key.

    Returns (shared_secret, ciphertext) in that order.

    NOTE the order: `cryptography` returns the SHARED SECRET FIRST. Swapping
    these silently produces a 1088-byte "secret" and a 32-byte "ciphertext",
    which then fails far away from the cause. This wrapper exists partly to
    make that mistake impossible to make twice.
    """
    shared_secret, ciphertext = public_key.encapsulate()
    if len(shared_secret) != MLKEM768_SS_LEN or len(ciphertext) != MLKEM768_CT_LEN:
        raise ValueError("unexpected ML-KEM-768 encapsulation output size")  # pragma: no cover
    return shared_secret, ciphertext


def mlkem768_decapsulate(private_key: mlkem.MLKEM768PrivateKey, ciphertext: bytes) -> bytes:
    """Decapsulate a ciphertext.

    IMPLICIT REJECTION (FIPS 203 section 7.3). A well-formed but tampered ciphertext
    does NOT raise. It returns a *different, pseudorandom* shared secret, by
    design -- distinguishing valid from invalid ciphertexts would break IND-CCA
    security. Verified empirically; see tests/test_pqc.py.

    The practical consequence for callers: a tampered ML-KEM ciphertext is
    detected downstream as an AEAD tag failure on the first message, NOT as an
    exception here. Code that expects decapsulation to raise on tampering is
    wrong, and so is a test that asserts it.

    A ciphertext of the wrong LENGTH does raise, and that we surface.
    """
    if len(ciphertext) != MLKEM768_CT_LEN:
        raise ValueError(
            f"ML-KEM-768 ciphertext must be {MLKEM768_CT_LEN} bytes, got {len(ciphertext)}"
        )
    return private_key.decapsulate(ciphertext)


def _self_check() -> None:
    """Fail at import if the library's ML-KEM parameters are not what we expect.

    Cheap (one keygen + one encapsulation) and it turns a silent parameter
    change in a dependency upgrade into an immediate, obvious startup failure.
    """
    private_key = generate_mlkem768_private_key()
    ek = mlkem768_encapsulation_key_bytes(private_key)
    if len(ek) != MLKEM768_EK_LEN:  # pragma: no cover - defensive
        raise RuntimeError(f"ML-KEM-768 ek is {len(ek)} bytes, expected {MLKEM768_EK_LEN}")
    shared, ciphertext = mlkem768_encapsulate(private_key.public_key())
    if mlkem768_decapsulate(private_key, ciphertext) != shared:  # pragma: no cover
        raise RuntimeError("ML-KEM-768 round trip failed")


_self_check()


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
