"""Server-side session table shared by the gateway (hop 1) and cloud (hop 2).

A session is the scope of one AEAD key. It ends when either the record budget
or the time-to-live is exhausted, at which point the client must re-handshake.
Rekeying matters here because hop 1 has no forward secrecy at all: a shorter
session life bounds how much data one derived key protects, even though it
cannot bound what a compromised static key exposes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .cryptoutil import AeadReceiver


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """RFC 3339 / ISO 8601 with a trailing Z, stable across platforms."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ServerSession:
    session_id: bytes
    client_id: str
    receiver: AeadReceiver
    expires_at: datetime
    max_records: int
    accepted: int = 0
    created_at: datetime = field(default_factory=utc_now)
    #: Negotiated suite, so logs and metrics can show whether the data that
    #: arrived on this session was protected post-quantum or not. Hop 1 has no
    #: negotiation and reports its fixed legacy suite.
    suite: str = "classical-p256"

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or utc_now()
        return now >= self.expires_at or self.accepted >= self.max_records


class SessionStore:
    """In-memory session table with lazy expiry.

    Not shared between replicas and not persisted -- a restart drops every
    session and clients re-handshake. Acceptable for the baseline; noted as a
    scaling weakness.
    """

    def __init__(self, ttl_seconds: int, max_records: int) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_records = max_records
        self._sessions: dict[bytes, ServerSession] = {}
        # Handshake nonces we have already answered, so a captured ClientHello
        # cannot be replayed into a second live session. Bounded by time.
        self._seen_nonces: dict[bytes, float] = {}

    def new_expiry(self) -> datetime:
        return utc_now() + timedelta(seconds=self.ttl_seconds)

    def remember_nonce(self, nonce: bytes) -> bool:
        """Record a handshake nonce. Returns False if we have seen it before."""
        self._prune_nonces()
        if nonce in self._seen_nonces:
            return False
        self._seen_nonces[nonce] = time.monotonic()
        return True

    def _prune_nonces(self) -> None:
        cutoff = time.monotonic() - (2 * self.ttl_seconds)
        stale = [n for n, seen in self._seen_nonces.items() if seen < cutoff]
        for nonce in stale:
            del self._seen_nonces[nonce]

    def put(self, session: ServerSession) -> None:
        self._sessions[session.session_id] = session

    def get(self, session_id: bytes) -> ServerSession | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.is_expired():
            del self._sessions[session_id]
            return None
        return session

    def drop(self, session_id: bytes) -> None:
        self._sessions.pop(session_id, None)

    def prune(self) -> int:
        expired = [sid for sid, sess in self._sessions.items() if sess.is_expired()]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    @property
    def active(self) -> int:
        return len(self._sessions)
