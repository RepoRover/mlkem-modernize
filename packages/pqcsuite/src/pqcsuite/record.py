"""AEAD record layer shared by both suites.

Key establishment is what differs between the legacy and post-quantum paths;
once a 32-byte session key exists the record layer is identical. Sharing it
means the migration changes exactly one thing, which is what makes the
before/after comparison meaningful.
"""

from __future__ import annotations

import math
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqcwire.frames import DataFrame, FrameError, nonce_for_seq
from pqcwire.protocol import PROTOCOL_VERSION
from pqcwire.sequence import SequenceCounter, SequenceGuard

KEY_LENGTH = 32
DEFAULT_MAX_RECORDS = 10_000
DEFAULT_MAX_AGE_SECONDS = 900.0


class AuthenticationError(FrameError):
    """Raised when a frame fails AEAD tag verification."""


class RecordSessionExhausted(FrameError):
    """Raised when an age or record ceiling requires a fresh handshake."""


class RecordSession:
    """Seals records and accepts only a bounded number under a short-lived key."""

    def __init__(
        self,
        suite: str,
        session_id: str,
        key: bytes,
        *,
        max_records: int = DEFAULT_MAX_RECORDS,
        max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
    ) -> None:
        if len(key) != KEY_LENGTH:
            raise ValueError(f"session key must be {KEY_LENGTH} bytes, got {len(key)}")
        if max_records < 1 or max_age_seconds <= 0 or not math.isfinite(max_age_seconds):
            raise ValueError("record limit and finite session age must be positive")
        self.suite = suite
        self.session_id = session_id
        self._aead = AESGCM(key)
        self._counter = SequenceCounter()
        self._guard = SequenceGuard()
        self._max_records = max_records
        self._max_age = max_age_seconds
        self._created_at = time.monotonic()
        self._sealed = 0
        self._opened = 0
        # Web handlers run in a thread pool, so two frames for one session can
        # be processed concurrently. Without this lock the sequence counter
        # could hand out a duplicate number, which would reuse an AES-GCM nonce.
        self._lock = threading.Lock()

    def seal(self, plaintext: bytes) -> DataFrame:
        with self._lock:
            self._require_usable(self._sealed)
            seq = self._counter.issue()
            frame = DataFrame(
                suite=self.suite,
                session_id=self.session_id,
                seq=seq,
                ciphertext=b"",
            )
            ciphertext = self._aead.encrypt(nonce_for_seq(seq), plaintext, frame.aad())
            self._sealed += 1
            return DataFrame(
                suite=self.suite,
                session_id=self.session_id,
                seq=seq,
                ciphertext=ciphertext,
            )

    def open(self, frame: DataFrame) -> bytes:
        if frame.version != PROTOCOL_VERSION:
            raise FrameError(f"unsupported protocol version {frame.version}")
        if frame.suite != self.suite:
            raise FrameError(
                f"frame suite {frame.suite!r} does not match session suite {self.suite!r}"
            )
        if frame.session_id != self.session_id:
            raise FrameError("frame belongs to a different session")

        with self._lock:
            self._require_usable(self._opened)
            self._guard.validate(frame.seq)
            try:
                plaintext = self._aead.decrypt(frame.nonce(), frame.ciphertext, frame.aad())
            except InvalidTag as exc:
                raise AuthenticationError("frame failed authentication") from exc
            self._guard.commit(frame.seq)
            self._opened += 1
            return plaintext

    def _require_usable(self, records: int) -> None:
        if time.monotonic() - self._created_at >= self._max_age:
            raise RecordSessionExhausted("session has expired; rekey required")
        if records >= self._max_records:
            raise RecordSessionExhausted("session record limit reached; rekey required")
