import pytest

from pqcnode import SessionAlreadyUsed, SessionHistoryFull, SessionStore
from pqcnode import sessions as sessions_module
from pqcsuite import record as record_module
from pqcsuite.record import RecordSession
from pqcwire.frames import FrameError
from pqcwire.protocol import HYBRID_PQC


def test_session_store_rejects_active_and_recent_identifier_reuse(monkeypatch):
    clock = {"now": 10.0}
    monkeypatch.setattr(sessions_module.time, "monotonic", lambda: clock["now"])
    store = SessionStore[str](
        ttl_seconds=5,
        max_entries=1,
        history_ttl_seconds=10,
        history_max_entries=2,
    )
    store.put("session", "first")

    with pytest.raises(SessionAlreadyUsed):
        store.put("session", "replacement")
    assert store.get("session") == "first"

    clock["now"] = 16.0
    with pytest.raises(SessionAlreadyUsed):
        store.put("session", "recent-replay")

    clock["now"] = 21.0
    store.put("session", "after-history-window")
    assert store.get("session") == "after-history-window"


def test_session_store_rejects_history_shorter_than_active_lifetime():
    with pytest.raises(ValueError, match="history TTL"):
        SessionStore[str](
            ttl_seconds=10,
            max_entries=1,
            history_ttl_seconds=5,
            history_max_entries=1,
        )


def test_session_identifier_history_fails_closed_until_ttl_recovery(monkeypatch):
    clock = {"now": 10.0}
    monkeypatch.setattr(sessions_module.time, "monotonic", lambda: clock["now"])
    store = SessionStore[str](
        ttl_seconds=5,
        max_entries=1,
        history_ttl_seconds=100,
        history_max_entries=2,
    )
    store.put("one", "one")
    store.put("two", "two")

    with pytest.raises(SessionHistoryFull):
        store.put("three", "three")
    with pytest.raises(SessionAlreadyUsed):
        store.put("one", "replay")
    assert list(store._used) == ["one", "two"]

    clock["now"] = 111.0
    store.put("three", "three")
    assert store.get("three") == "three"


def test_sender_and_receiver_record_count_limits_require_rekey():
    key = b"k" * 32
    limited_sender = RecordSession(HYBRID_PQC, "session", key, max_records=2)
    receiver = RecordSession(HYBRID_PQC, "session", key, max_records=2)

    for payload in (b"one", b"two"):
        assert receiver.open(limited_sender.seal(payload)) == payload

    with pytest.raises(FrameError, match="record limit"):
        limited_sender.seal(b"three")

    unlimited_sender = RecordSession(HYBRID_PQC, "fedcba9876543210", key, max_records=3)
    limited_receiver = RecordSession(HYBRID_PQC, "fedcba9876543210", key, max_records=2)
    frames = [unlimited_sender.seal(payload) for payload in (b"one", b"two", b"three")]
    assert [limited_receiver.open(frame) for frame in frames[:2]] == [b"one", b"two"]
    with pytest.raises(FrameError, match="record limit"):
        limited_receiver.open(frames[2])


def test_sender_and_receiver_session_age_limits_require_rekey(monkeypatch):
    clock = {"now": 10.0}
    monkeypatch.setattr(record_module.time, "monotonic", lambda: clock["now"])
    sender = RecordSession(HYBRID_PQC, "0123456789abcdef", b"k" * 32, max_age_seconds=5)
    receiver = RecordSession(
        HYBRID_PQC,
        "0123456789abcdef",
        b"k" * 32,
        max_age_seconds=5,
    )
    frame = sender.seal(b"late")

    clock["now"] = 15.0
    with pytest.raises(FrameError, match="expired"):
        sender.seal(b"later")
    with pytest.raises(FrameError, match="expired"):
        receiver.open(frame)
