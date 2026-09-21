"""Wire frames and the canonical associated-data encoding.

Both peers must derive byte-identical associated data, so the encoding lives
here rather than in either cryptographic suite. Fields are length-prefixed
instead of delimiter-joined: a delimiter would let two different field
splittings produce the same AAD, which is exactly the kind of ambiguity that
turns into a splicing attack.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pqcwire.protocol import PROTOCOL_VERSION

# AES-GCM nonces are derived from the sequence number rather than transmitted.
# A fresh session key per session plus a strictly increasing 96-bit counter
# means a nonce is never reused. The cap makes that argument enforceable.
NONCE_LENGTH = 12
MAX_SEQ = 2**32 - 1

_AAD_CONTEXT = b"mlkem-modernize/aad/v1"


class FrameError(ValueError):
    """Raised when a frame cannot be decoded or fails validation."""


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise FrameError("field is not valid base64") from exc


def lp(raw: bytes) -> bytes:
    """Length-prefix a field so the concatenation is unambiguous."""
    return len(raw).to_bytes(4, "big") + raw


def canonical(*fields: bytes) -> bytes:
    """Concatenate length-prefixed fields into an unambiguous byte string."""
    return b"".join(lp(field) for field in fields)


_lp = lp


def nonce_for_seq(seq: int) -> bytes:
    if not 0 <= seq <= MAX_SEQ:
        raise FrameError(f"sequence number {seq} outside the safe nonce range")
    return seq.to_bytes(NONCE_LENGTH, "big")


def data_aad(version: int, suite: str, session_id: str, seq: int) -> bytes:
    """Associated data bound into every AES-GCM data frame.

    Binding the suite blocks downgrade-by-relabelling; binding the session id
    blocks splicing frames between sessions; binding the sequence number blocks
    reordering and replay within a session.
    """
    return b"".join(
        [
            _lp(_AAD_CONTEXT),
            _lp(version.to_bytes(4, "big")),
            _lp(suite.encode("utf-8")),
            _lp(session_id.encode("utf-8")),
            _lp(seq.to_bytes(8, "big")),
        ]
    )


def _require(mapping: Mapping[str, Any], key: str, kind: type) -> Any:
    if key not in mapping:
        raise FrameError(f"frame is missing required field {key!r}")
    value = mapping[key]
    if not isinstance(value, kind) or (isinstance(value, bool) and kind is int):
        raise FrameError(f"field {key!r} has wrong type")
    return value


@dataclass(frozen=True)
class HandshakeRequest:
    """Carries the initiator's key-encapsulation output to the responder.

    ``kem_payload`` is suite-specific and base64-encoded; the legacy suite puts
    an RSA-OAEP ciphertext there, the hybrid suite an ML-KEM ciphertext plus an
    X25519 public key.
    """

    suite: str
    session_id: str
    kem_payload: dict[str, str]
    version: int = PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.version,
            "suite": self.suite,
            "session_id": self.session_id,
            "kem": dict(self.kem_payload),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> HandshakeRequest:
        kem = _require(raw, "kem", dict)
        for key, value in kem.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise FrameError("kem payload must map strings to base64 strings")
        return cls(
            version=_require(raw, "v", int),
            suite=_require(raw, "suite", str),
            session_id=_require(raw, "session_id", str),
            kem_payload=dict(kem),
        )


@dataclass(frozen=True)
class DataFrame:
    """One AEAD-protected telemetry payload."""

    suite: str
    session_id: str
    seq: int
    ciphertext: bytes
    version: int = PROTOCOL_VERSION

    def aad(self) -> bytes:
        return data_aad(self.version, self.suite, self.session_id, self.seq)

    def nonce(self) -> bytes:
        return nonce_for_seq(self.seq)

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.version,
            "suite": self.suite,
            "session_id": self.session_id,
            "seq": self.seq,
            "ct": b64e(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DataFrame:
        seq = _require(raw, "seq", int)
        if not 0 <= seq <= MAX_SEQ:
            raise FrameError(f"sequence number {seq} outside the safe nonce range")
        return cls(
            version=_require(raw, "v", int),
            suite=_require(raw, "suite", str),
            session_id=_require(raw, "session_id", str),
            seq=seq,
            ciphertext=b64d(_require(raw, "ct", str)),
        )


def dumps(frame: Any) -> str:
    return json.dumps(frame.to_dict(), separators=(",", ":"), sort_keys=True)


def loads(text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        raise FrameError("frame is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise FrameError("frame must be a JSON object")
    return parsed
