"""AEAD record layer shared by both suites.

Key establishment is what differs between the legacy and post-quantum paths;
once a 32-byte session key exists the record layer is identical. Sharing it
means the migration changes exactly one thing, which is what makes the
before/after comparison meaningful.
"""

from __future__ import annotations

import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from wire.frames import DataFrame, FrameError, nonce_for_seq
from wire.sequence import SequenceCounter, SequenceGuard

KEY_LENGTH = 32


class AuthenticationError(FrameError):
    """Raised when a frame fails AEAD tag verification."""


class RecordSession:
    """Seals and opens frames under one established session key."""

    def __init__(self, suite: str, session_id: str, key: bytes) -> None:
        if len(key) != KEY_LENGTH:
            raise ValueError(f"session key must be {KEY_LENGTH} bytes, got {len(key)}")
        self.suite = suite
        self.session_id = session_id
        self._aead = AESGCM(key)
        self._counter = SequenceCounter()
        self._guard = SequenceGuard()
        # Web handlers run in a thread pool, so two frames for one session can
        # be processed concurrently. Without this lock the sequence counter
        # could hand out a duplicate number, which would reuse an AES-GCM nonce.
        self._lock = threading.Lock()

    def seal(self, plaintext: bytes) -> DataFrame:
        with self._lock:
            seq = self._counter.issue()
        frame = DataFrame(
            suite=self.suite,
            session_id=self.session_id,
            seq=seq,
            ciphertext=b"",
        )
        ciphertext = self._aead.encrypt(nonce_for_seq(seq), plaintext, frame.aad())
        return DataFrame(
            suite=self.suite,
            session_id=self.session_id,
            seq=seq,
            ciphertext=ciphertext,
        )

    def open(self, frame: DataFrame) -> bytes:
        if frame.suite != self.suite:
            raise FrameError(
                f"frame suite {frame.suite!r} does not match session suite {self.suite!r}"
            )
        if frame.session_id != self.session_id:
            raise FrameError("frame belongs to a different session")

        with self._lock:
            self._guard.validate(frame.seq)
            try:
                plaintext = self._aead.decrypt(frame.nonce(), frame.ciphertext, frame.aad())
            except InvalidTag as exc:
                raise AuthenticationError("frame failed authentication") from exc
            self._guard.commit(frame.seq)
            return plaintext
