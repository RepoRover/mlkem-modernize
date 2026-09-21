"""The modernized post-quantum key-establishment mechanism.

Every weakness catalogued in :mod:`pqcsuite.legacy` is addressed here:

* **Post-quantum confidentiality.** ML-KEM-768 replaces RSA transport, so a
  quantum adversary gains nothing from archived traffic.
* **Hybrid.** The session key also absorbs an X25519 exchange. The construction
  stays secure as long as *either* the lattice or the curve problem holds, so
  adopting a young primitive costs nothing against classical attackers.
* **Forward secrecy.** The responder's KEM keys are ephemeral and per-session.
  Compromising the long-term identity key later reveals nothing about past
  sessions -- the property the legacy suite most conspicuously lacks.
* **Mutual authentication.** The cloud signs each ephemeral offer and the
  gateway signs its complete request transcript with separately pinned
  ML-DSA-65 identities.
* **Transcript binding.** The key derivation absorbs a hash of every public
  value in the handshake, so a shared secret cannot be transplanted into a
  different context.

Secret ordering in the combiner is ``ss_pq || ss_ec``, matching the
``X25519MLKEM768`` group as deployed in TLS.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqcsuite.capabilities import CapabilityError, mlkem_module
from pqcsuite.record import KEY_LENGTH, RecordSession
from pqcwire.frames import FrameError, HandshakeRequest, b64d, b64e, canonical
from pqcwire.protocol import HYBRID_PQC, PROTOCOL_VERSION

_OFFER_CONTEXT = b"mlkem-modernize/offer/v1"
_TRANSCRIPT_CONTEXT = b"mlkem-modernize/transcript/v1"
_GATEWAY_AUTH_CONTEXT = b"mlkem-modernize/gateway-auth/v1"

X25519_PUBLIC_LENGTH = 32
DEFAULT_OFFER_TTL_SECONDS = 60.0
DEFAULT_MAX_PENDING_OFFERS = 128


class OfferCapacityError(RuntimeError):
    """Raised when the bounded ephemeral-offer store is full."""


def _mldsa() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:  # pragma: no cover - depends on the installed build
        raise CapabilityError("ML-DSA is unavailable; cryptography>=48 required") from exc
    return mldsa


def _x25519_public_bytes(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def generate_identity_key() -> Any:
    """Create the responder's long-term ML-DSA-65 signing key."""
    return _mldsa().MLDSA65PrivateKey.generate()


def serialize_identity_private(key: Any) -> bytes:
    # The ML-DSA classes are reached through a guarded import and are therefore
    # untyped here; narrow the value rather than leaking Any to callers.
    return bytes(key.private_bytes_raw())


def load_identity_private(seed: bytes) -> Any:
    return _mldsa().MLDSA65PrivateKey.from_seed_bytes(seed)


def serialize_identity_public(key: Any) -> bytes:
    return bytes(key.public_bytes_raw())


def load_identity_public(raw: bytes) -> Any:
    return _mldsa().MLDSA65PublicKey.from_public_bytes(raw)


@dataclass(frozen=True)
class Offer:
    """A signed, per-session set of ephemeral responder public keys."""

    key_id: str
    mlkem_pub: bytes
    x25519_pub: bytes
    signature: bytes
    version: int = PROTOCOL_VERSION
    suite: str = HYBRID_PQC

    def signed_bytes(self) -> bytes:
        return canonical(
            _OFFER_CONTEXT,
            self.version.to_bytes(4, "big"),
            self.suite.encode("utf-8"),
            self.key_id.encode("utf-8"),
            self.mlkem_pub,
            self.x25519_pub,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.version,
            "suite": self.suite,
            "key_id": self.key_id,
            "mlkem_pub": b64e(self.mlkem_pub),
            "x25519_pub": b64e(self.x25519_pub),
            "signature": b64e(self.signature),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Offer:
        try:
            version = raw["v"]
            suite = raw["suite"]
            key_id = raw["key_id"]
            if not isinstance(version, int) or isinstance(version, bool):
                raise FrameError("offer protocol version has the wrong type")
            if version != PROTOCOL_VERSION:
                raise FrameError(f"unsupported protocol version {version}")
            if not isinstance(suite, str) or suite != HYBRID_PQC:
                raise FrameError(f"unsupported offer suite {suite!r}")
            if not isinstance(key_id, str) or not key_id:
                raise FrameError("offer key_id must be a non-empty string")
            return cls(
                key_id=key_id,
                mlkem_pub=b64d(raw["mlkem_pub"]),
                x25519_pub=b64d(raw["x25519_pub"]),
                signature=b64d(raw["signature"]),
                version=version,
                suite=suite,
            )
        except KeyError as exc:
            raise FrameError(f"offer is missing field {exc}") from None


def _transcript_hash(
    version: int,
    suite: str,
    session_id: str,
    offer: Offer,
    mlkem_ct: bytes,
    client_x25519_pub: bytes,
) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(
        canonical(
            _TRANSCRIPT_CONTEXT,
            version.to_bytes(4, "big"),
            suite.encode("utf-8"),
            offer.version.to_bytes(4, "big"),
            offer.suite.encode("utf-8"),
            session_id.encode("utf-8"),
            offer.key_id.encode("utf-8"),
            offer.mlkem_pub,
            offer.x25519_pub,
            mlkem_ct,
            client_x25519_pub,
        )
    )
    return digest.finalize()


def _gateway_auth_bytes(transcript: bytes) -> bytes:
    return canonical(_GATEWAY_AUTH_CONTEXT, transcript)


def _combine(ss_pq: bytes, ss_ec: bytes, transcript: bytes) -> bytes:
    """Derive the session key from both shared secrets.

    Concatenate-then-KDF: the transcript hash enters as the HKDF salt, so the
    output is bound to the exact handshake that produced it.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=transcript,
        info=HYBRID_PQC.encode("utf-8"),
    ).derive(ss_pq + ss_ec)


class HybridServer:
    """Cloud side: issues signed ephemeral offers and completes handshakes."""

    suite = HYBRID_PQC

    def __init__(
        self,
        identity_key: Any,
        gateway_identity_public_key: Any,
        ttl_seconds: float = DEFAULT_OFFER_TTL_SECONDS,
        max_pending_offers: int = DEFAULT_MAX_PENDING_OFFERS,
    ) -> None:
        if ttl_seconds <= 0 or max_pending_offers < 1:
            raise ValueError("offer TTL and pending-offer capacity must be positive")
        self._identity_key = identity_key
        self._gateway_identity = gateway_identity_public_key
        self._ttl = ttl_seconds
        self._max_pending = max_pending_offers
        self._pending: dict[str, tuple[Any, x25519.X25519PrivateKey, float]] = {}
        self._lock = threading.Lock()

    @property
    def identity_public_key(self) -> Any:
        return self._identity_key.public_key()

    @property
    def pending_offers(self) -> int:
        with self._lock:
            self._expire_locked()
            return len(self._pending)

    def _expire_locked(self) -> None:
        """Drop ephemeral keys past their TTL.

        Bounding the lifetime bounds the window in which a stolen responder
        process could still complete a handshake, and stops an attacker from
        exhausting memory by requesting offers it never uses.
        """
        now = time.monotonic()
        stale = [key_id for key_id, (_, _, expiry) in self._pending.items() if expiry <= now]
        for key_id in stale:
            del self._pending[key_id]

    def make_offer(self) -> Offer:
        with self._lock:
            self._expire_locked()
            if len(self._pending) >= self._max_pending:
                raise OfferCapacityError("pending hybrid offer capacity is exhausted")
            mlkem = mlkem_module()
            key_id = os.urandom(8).hex()
            mlkem_private = mlkem.MLKEM768PrivateKey.generate()
            x_private = x25519.X25519PrivateKey.generate()

            unsigned = Offer(
                key_id=key_id,
                mlkem_pub=mlkem_private.public_key().public_bytes_raw(),
                x25519_pub=_x25519_public_bytes(x_private.public_key()),
                signature=b"",
            )
            signature = self._identity_key.sign(unsigned.signed_bytes())
            self._pending[key_id] = (mlkem_private, x_private, time.monotonic() + self._ttl)
            return Offer(
                key_id=key_id,
                mlkem_pub=unsigned.mlkem_pub,
                x25519_pub=unsigned.x25519_pub,
                signature=signature,
            )

    def accept(self, request: HandshakeRequest) -> RecordSession:
        if request.suite != self.suite:
            raise FrameError(f"handshake suite {request.suite!r} is not {self.suite!r}")
        if request.version != PROTOCOL_VERSION:
            raise FrameError(f"unsupported protocol version {request.version}")

        try:
            key_id = request.kem_payload["key_id"]
            mlkem_ct = b64d(request.kem_payload["mlkem_ct"])
            client_x25519_pub = b64d(request.kem_payload["x25519_pub"])
            gateway_signature = b64d(request.kem_payload["gateway_signature"])
        except KeyError as exc:
            raise FrameError(f"hybrid handshake is missing field {exc}") from None

        # Look up without consuming first: unauthenticated garbage must not be
        # able to burn scarce offers. The authenticated request atomically pops
        # the entry below before any key agreement runs.
        with self._lock:
            self._expire_locked()
            entry = self._pending.get(key_id)
        if entry is None:
            raise FrameError(f"offer {key_id!r} is unknown, expired, or already used")
        mlkem_private, x_private, _ = entry

        if len(client_x25519_pub) != X25519_PUBLIC_LENGTH:
            raise FrameError("client X25519 public key has the wrong length")

        offer = Offer(
            key_id=key_id,
            mlkem_pub=mlkem_private.public_key().public_bytes_raw(),
            x25519_pub=_x25519_public_bytes(x_private.public_key()),
            signature=b"",
        )
        transcript = _transcript_hash(
            request.version,
            request.suite,
            request.session_id,
            offer,
            mlkem_ct,
            client_x25519_pub,
        )
        try:
            self._gateway_identity.verify(gateway_signature, _gateway_auth_bytes(transcript))
        except InvalidSignature as exc:
            raise FrameError("gateway handshake signature is invalid") from exc

        with self._lock:
            self._expire_locked()
            consumed = self._pending.pop(key_id, None)
        if consumed is not entry:
            raise FrameError(f"offer {key_id!r} is unknown, expired, or already used")

        try:
            ss_pq = mlkem_private.decapsulate(mlkem_ct)
        except ValueError as exc:
            raise FrameError("ML-KEM decapsulation rejected the ciphertext") from exc

        ss_ec = x_private.exchange(x25519.X25519PublicKey.from_public_bytes(client_x25519_pub))
        return RecordSession(self.suite, request.session_id, _combine(ss_pq, ss_ec, transcript))


class HybridClient:
    """Gateway side: verifies the offer and authenticates its response."""

    suite = HYBRID_PQC

    def __init__(self, peer_identity_public_key: Any, identity_key: Any) -> None:
        self._peer_identity = peer_identity_public_key
        self._identity_key = identity_key

    def verify_offer(self, offer: Offer) -> None:
        if offer.version != PROTOCOL_VERSION:
            raise FrameError(f"unsupported protocol version {offer.version}")
        if offer.suite != self.suite:
            raise FrameError(f"offer suite {offer.suite!r} is not {self.suite!r}")
        try:
            self._peer_identity.verify(offer.signature, offer.signed_bytes())
        except InvalidSignature as exc:
            raise FrameError("offer signature is invalid") from exc

    def open_session(
        self, offer: Offer, session_id: str | None = None
    ) -> tuple[HandshakeRequest, RecordSession]:
        self.verify_offer(offer)
        mlkem = mlkem_module()
        session_id = session_id or os.urandom(8).hex()

        peer_mlkem = mlkem.MLKEM768PublicKey.from_public_bytes(offer.mlkem_pub)
        # NOTE: encapsulate() returns (shared_secret, ciphertext) -- the reverse
        # of the ordering most examples assume. Swapping them fails only later,
        # at decapsulation, with a misleading "invalid ciphertext" error.
        ss_pq, mlkem_ct = peer_mlkem.encapsulate()

        x_private = x25519.X25519PrivateKey.generate()
        client_x25519_pub = _x25519_public_bytes(x_private.public_key())
        ss_ec = x_private.exchange(x25519.X25519PublicKey.from_public_bytes(offer.x25519_pub))

        transcript = _transcript_hash(
            PROTOCOL_VERSION,
            self.suite,
            session_id,
            offer,
            mlkem_ct,
            client_x25519_pub,
        )
        unsigned_request = HandshakeRequest(
            suite=self.suite,
            session_id=session_id,
            kem_payload={
                "key_id": offer.key_id,
                "mlkem_ct": b64e(mlkem_ct),
                "x25519_pub": b64e(client_x25519_pub),
            },
        )
        request = self.authenticate_request(unsigned_request, offer)
        return request, RecordSession(self.suite, session_id, _combine(ss_pq, ss_ec, transcript))

    def authenticate_request(self, request: HandshakeRequest, offer: Offer) -> HandshakeRequest:
        """Sign every transcript field in a fully constructed gateway request."""
        try:
            mlkem_ct = b64d(request.kem_payload["mlkem_ct"])
            client_x25519_pub = b64d(request.kem_payload["x25519_pub"])
        except KeyError as exc:
            raise FrameError(f"hybrid handshake is missing field {exc}") from None
        transcript = _transcript_hash(
            request.version,
            request.suite,
            request.session_id,
            offer,
            mlkem_ct,
            client_x25519_pub,
        )
        return HandshakeRequest(
            suite=request.suite,
            session_id=request.session_id,
            version=request.version,
            kem_payload={
                **request.kem_payload,
                "gateway_signature": b64e(self._identity_key.sign(_gateway_auth_bytes(transcript))),
            },
        )
