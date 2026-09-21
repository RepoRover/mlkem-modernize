"""The legacy key-establishment mechanism (v0 baseline).

This is the mechanism the modernization replaces, and it is written the way
fielded firmware from the RSA era actually looks. Three defects are
deliberate and are the subject of the baseline analysis:

1. **No key derivation.** The secret transported under RSA-OAEP is used
   directly as the AES-256-GCM key. There is no domain separation, so the same
   secret could not safely be reused for any other purpose.
2. **No transcript binding.** The RSA ciphertext is not bound to the session
   identifier, so a network attacker can replay a captured handshake under a
   different label and obtain a session with the same key.
3. **No forward secrecy.** The key is transported under a static long-term RSA
   key. Recovering that one key retroactively decrypts every archived session,
   which is precisely the harvest-now-decrypt-later exposure.

Defect 3 is the one a quantum adversary turns into a break; defects 1 and 2
are classical hygiene failures that the migration also fixes.
"""

from __future__ import annotations

import os
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pqcsuite.record import KEY_LENGTH, RecordSession
from pqcwire.frames import FrameError, HandshakeRequest, b64d, b64e
from pqcwire.protocol import LEGACY_RSA, PROTOCOL_VERSION

RSA_KEY_BITS = 2048
PUBLIC_EXPONENT = 65537

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=RSA_KEY_BITS)


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("expected an RSA public key")
    return key


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    # Unencrypted on purpose: the demo hands this exact file to the attacker to
    # stand in for a successful Shor's-algorithm recovery of the key.
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("expected an RSA private key")
    return key


def new_session_id() -> str:
    return os.urandom(8).hex()


class LegacyClient:
    """Device side: transports a fresh secret under the responder's RSA key."""

    suite = LEGACY_RSA

    def __init__(self, peer_public_key: rsa.RSAPublicKey) -> None:
        self._peer_public_key = peer_public_key

    def open_session(self, session_id: str | None = None) -> tuple[HandshakeRequest, RecordSession]:
        session_id = session_id or new_session_id()
        secret = secrets.token_bytes(KEY_LENGTH)
        rsa_ct = self._peer_public_key.encrypt(secret, _OAEP)
        request = HandshakeRequest(
            suite=self.suite,
            session_id=session_id,
            kem_payload={"rsa_ct": b64e(rsa_ct)},
        )
        # Defect 1: the transported secret becomes the key with no KDF applied.
        return request, RecordSession(self.suite, session_id, secret)


class LegacyServer:
    """Gateway side: recovers the transported secret with its long-term key."""

    suite = LEGACY_RSA

    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self._private_key.public_key()

    def accept(self, request: HandshakeRequest) -> RecordSession:
        if request.version != PROTOCOL_VERSION:
            raise FrameError(f"unsupported protocol version {request.version}")
        if request.suite != self.suite:
            raise FrameError(f"handshake suite {request.suite!r} is not {self.suite!r}")
        try:
            rsa_ct = b64d(request.kem_payload["rsa_ct"])
        except KeyError:
            raise FrameError("legacy handshake is missing 'rsa_ct'") from None

        # Defect 2: nothing here binds rsa_ct to request.session_id.
        secret = self._private_key.decrypt(rsa_ct, _OAEP)
        if len(secret) != KEY_LENGTH:
            raise FrameError("transported secret has the wrong length")
        return RecordSession(self.suite, request.session_id, secret)


def recover_session_key(private_key: rsa.RSAPrivateKey, request: HandshakeRequest) -> bytes:
    """Recover a session key from a captured handshake.

    Used by the attacker tooling. That this function is a three-line wrapper
    over ``decrypt`` is the entire point: once the long-term key falls, every
    archived session key follows immediately.
    """
    rsa_ct = b64d(request.kem_payload["rsa_ct"])
    secret = private_key.decrypt(rsa_ct, _OAEP)
    if len(secret) != KEY_LENGTH:
        raise FrameError("transported secret has the wrong length")
    return secret
