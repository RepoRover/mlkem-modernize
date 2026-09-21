"""Bounded, expiring storage for established sessions.

Handshakes are unauthenticated at the transport level, so anyone who can reach
a node can ask it to create session state. The store is therefore bounded in
both age and count: without a cap, session creation is a memory-exhaustion
denial of service.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Generic, TypeVar

T = TypeVar("T")

DEFAULT_TTL_SECONDS = 900.0
DEFAULT_MAX_ENTRIES = 512


class SessionNotFound(KeyError):
    """Raised when a session id is unknown or has expired."""


class SessionStore(Generic[T]):
    def __init__(
        self,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._entries: OrderedDict[str, tuple[T, float]] = OrderedDict()
        self._lock = threading.Lock()
        self.evicted = 0
        self.expired = 0

    def put(self, key: str, value: T) -> None:
        with self._lock:
            self._expire_locked()
            if key in self._entries:
                del self._entries[key]
            elif len(self._entries) >= self._max_entries:
                self._entries.popitem(last=False)
                self.evicted += 1
            self._entries[key] = (value, time.monotonic() + self._ttl)

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

    def _expire_locked(self) -> None:
        now = time.monotonic()
        stale = [key for key, (_, expiry) in self._entries.items() if expiry <= now]
        for key in stale:
            del self._entries[key]
        self.expired += len(stale)
