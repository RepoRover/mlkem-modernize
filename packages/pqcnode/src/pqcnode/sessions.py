"""Bounded, expiring storage for established sessions.

Anyone who can reach a handshake endpoint can make it perform parsing and, on
the legacy path, create state. Active sessions and recently used identifiers
are therefore bounded in age and count. Identifier history also prevents a
replayed handshake from replacing a live session and resetting replay state.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Generic, TypeVar

T = TypeVar("T")

DEFAULT_TTL_SECONDS = 900.0
DEFAULT_MAX_ENTRIES = 512
DEFAULT_HISTORY_TTL_SECONDS = 1800.0
DEFAULT_HISTORY_MAX_ENTRIES = 1024


class SessionNotFound(KeyError):
    """Raised when a session id is unknown or has expired."""


class SessionAlreadyUsed(KeyError):
    """Raised when a handshake reuses an active or recently used identifier."""


class SessionHistoryFull(RuntimeError):
    """Raised when admitting state would evict an unexpired replay marker."""


class SessionStore(Generic[T]):
    def __init__(
        self,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        history_ttl_seconds: float = DEFAULT_HISTORY_TTL_SECONDS,
        history_max_entries: int = DEFAULT_HISTORY_MAX_ENTRIES,
    ) -> None:
        if ttl_seconds <= 0 or history_ttl_seconds < ttl_seconds:
            raise ValueError("history TTL must be at least the positive session TTL")
        if max_entries < 1 or history_max_entries < max_entries:
            raise ValueError("history capacity must be at least the active session capacity")
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._history_ttl = history_ttl_seconds
        self._history_max_entries = history_max_entries
        self._entries: OrderedDict[str, tuple[T, float]] = OrderedDict()
        self._used: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()
        self.evicted = 0
        self.expired = 0

    def ensure_unused(self, key: str) -> None:
        """Reject a known identifier before expensive handshake work.

        Callers must still use :meth:`put`, whose atomic check closes the race
        between concurrent handshakes that both passed this preflight.
        """
        with self._lock:
            now = time.monotonic()
            self._expire_locked(now)
            self._expire_history_locked(now)
            self._ensure_unused_locked(key)
            self._ensure_history_capacity_locked()

    def put(self, key: str, value: T) -> None:
        with self._lock:
            now = time.monotonic()
            self._expire_locked(now)
            self._expire_history_locked(now)
            self._ensure_unused_locked(key)
            self._ensure_history_capacity_locked()
            if len(self._entries) >= self._max_entries:
                self._entries.popitem(last=False)
                self.evicted += 1
            self._entries[key] = (value, now + self._ttl)
            self._used[key] = now + self._history_ttl

    def get(self, key: str) -> T:
        with self._lock:
            self._expire_locked()
            entry = self._entries.get(key)
            if entry is None:
                raise SessionNotFound(key)
            # Refresh recency so an active session is not evicted ahead of an
            # idle one under pressure.
            self._entries.move_to_end(key)
            return entry[0]

    def pop(self, key: str) -> T:
        with self._lock:
            self._expire_locked()
            entry = self._entries.pop(key, None)
            if entry is None:
                raise SessionNotFound(key)
            return entry[0]

    def drop(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def peek(self, key: str) -> T | None:
        try:
            return self.get(key)
        except SessionNotFound:
            return None

    def __len__(self) -> int:
        with self._lock:
            self._expire_locked()
            return len(self._entries)

    def _expire_locked(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        stale = [key for key, (_, expiry) in self._entries.items() if expiry <= now]
        for key in stale:
            del self._entries[key]
        self.expired += len(stale)

    def _ensure_unused_locked(self, key: str) -> None:
        if key in self._entries or key in self._used:
            raise SessionAlreadyUsed(key)

    def _ensure_history_capacity_locked(self) -> None:
        if len(self._used) >= self._history_max_entries:
            raise SessionHistoryFull("session identifier history capacity is exhausted")

    def _expire_history_locked(self, now: float) -> None:
        stale = [key for key, expiry in self._used.items() if expiry <= now]
        for key in stale:
            del self._used[key]
