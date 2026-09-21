"""Replay and reordering protection, shared by every cipher suite.

Frames travel over ordered, reliable transport, so a strictly increasing
counter is the right check: anything at or below the high-water mark is either
a replay or a reorder, and both are rejected. A sliding window would only be
needed on a lossy datagram transport.
"""

from __future__ import annotations

from pqcwire.frames import MAX_SEQ, FrameError


class ReplayError(FrameError):
    """Raised when a frame repeats or regresses the sequence number."""


class SequenceGuard:
    """Tracks the highest accepted sequence number for one direction."""

    __slots__ = ("_highest",)

    def __init__(self) -> None:
        self._highest = -1

    @property
    def highest(self) -> int:
        return self._highest

    def validate(self, seq: int) -> None:
        """Check a sequence number without advancing the high-water mark."""
        if seq <= self._highest:
            raise ReplayError(
                f"frame seq {seq} replays or regresses high-water mark {self._highest}"
            )
        if seq > MAX_SEQ:
            raise FrameError(f"sequence number {seq} outside the safe nonce range")

    def commit(self, seq: int) -> None:
        """Advance the high-water mark once the frame has been authenticated.

        Committing only after tag verification stops an attacker from
        desynchronising the session by injecting a forged frame with a high
        sequence number.
        """
        self._highest = seq

    def accept(self, seq: int) -> None:
        self.validate(seq)
        self.commit(seq)


class SequenceCounter:
    """Issues strictly increasing sequence numbers for the sending direction."""

    __slots__ = ("_next",)

    def __init__(self) -> None:
        self._next = 0

    def issue(self) -> int:
        if self._next > MAX_SEQ:
            raise FrameError("session exhausted its nonce space; rekey required")
        seq = self._next
        self._next += 1
        return seq
