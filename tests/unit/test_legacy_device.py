import io
import urllib.error
from types import SimpleNamespace

import pytest

import pqcsuite as cs
from pqcsuite import record as record_module
from pqcwire.telemetry import WeatherReading
from services.legacy_device import device

READING = WeatherReading("2024-01-01", 7.4, 3.4, 1.8, 19.7)


def _config():
    return SimpleNamespace(gateway_url="http://gateway", timeout=1.0)


def test_current_reading_is_retried_once_after_local_session_expiry(monkeypatch):
    clock = {"now": 0.0}
    monkeypatch.setattr(record_module.time, "monotonic", lambda: clock["now"])
    private_key = cs.generate_private_key()
    pem = cs.serialize_public_key(private_key.public_key())
    calls = []

    def post(url, payload, timeout):
        calls.append(url)
        return {}

    monkeypatch.setattr(device, "_post_json", post)
    first = device._establish_session(_config(), pem)
    clock["now"] = 901.0

    replacement = device._send_with_rehandshake(_config(), pem, first, READING)

    assert replacement is not first
    assert calls.count("http://gateway/legacy/session") == 2
    assert calls.count("http://gateway/legacy/frames") == 1


def test_gateway_conflict_requests_one_rehandshake(monkeypatch):
    private_key = cs.generate_private_key()
    pem = cs.serialize_public_key(private_key.public_key())
    frame_calls = 0

    def post(url, payload, timeout):
        nonlocal frame_calls
        if url.endswith("/legacy/frames"):
            frame_calls += 1
            if frame_calls == 1:
                raise urllib.error.HTTPError(url, 409, "expired", {}, io.BytesIO(b"expired"))
        return {}

    monkeypatch.setattr(device, "_post_json", post)
    first = device._establish_session(_config(), pem)
    replacement = device._send_with_rehandshake(_config(), pem, first, READING)

    assert replacement is not first
    assert frame_calls == 2


def test_second_session_failure_is_not_retried_indefinitely(monkeypatch):
    private_key = cs.generate_private_key()
    pem = cs.serialize_public_key(private_key.public_key())
    session = device._establish_session
    rehandshakes = 0

    def establish(config, public_key):
        nonlocal rehandshakes
        rehandshakes += 1
        return object()

    def reject(config, current, reading):
        raise device.SessionNeedsRehandshake("still exhausted")

    monkeypatch.setattr(device, "_establish_session", establish)
    monkeypatch.setattr(device, "_send", reject)

    with pytest.raises(device.SessionNeedsRehandshake):
        device._send_with_rehandshake(_config(), pem, session, READING)
    assert rehandshakes == 1
