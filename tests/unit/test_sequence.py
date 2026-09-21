import pytest

from wire.frames import MAX_SEQ, FrameError
from wire.sequence import ReplayError, SequenceCounter, SequenceGuard


def test_counter_issues_strictly_increasing_values():
    counter = SequenceCounter()
    assert [counter.issue() for _ in range(5)] == [0, 1, 2, 3, 4]


def test_counter_refuses_to_exhaust_the_nonce_space():
    counter = SequenceCounter()
    counter._next = MAX_SEQ + 1
    with pytest.raises(FrameError, match="rekey"):
        counter.issue()


def test_guard_accepts_increasing_sequence_numbers():
    guard = SequenceGuard()
    for seq in (0, 1, 5, 99):
        guard.accept(seq)
    assert guard.highest == 99


@pytest.mark.parametrize("replayed", [0, 3, 5])
def test_guard_rejects_replays_and_reorders(replayed):
    guard = SequenceGuard()
    guard.accept(5)
    with pytest.raises(ReplayError):
        guard.accept(replayed)


def test_validate_does_not_advance_the_high_water_mark():
    """A frame that fails authentication must not desynchronise the session."""
    guard = SequenceGuard()
    guard.accept(1)
    guard.validate(9)  # looks valid, but suppose the AEAD tag then fails
    assert guard.highest == 1
    guard.accept(2)  # the genuine next frame is still accepted
    assert guard.highest == 2
