import gzip
import importlib
import json
import time

import httpx
from fastapi.testclient import TestClient


def _tap(tmp_path, monkeypatch, handler, **limits):
    monkeypatch.setenv("CAPTURE_PATH", str(tmp_path / "capture.jsonl"))
    monkeypatch.setenv("TAP_UPSTREAM_URL", "http://upstream")
    for name, value in limits.items():
        monkeypatch.setenv(name, str(value))

    import services.tap.app as tap_module

    tap_module = importlib.reload(tap_module)
    tap_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return tap_module


def test_tap_rejects_oversized_request_before_forwarding(tmp_path, monkeypatch):
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"ok")

    tap = _tap(tmp_path, monkeypatch, handler, MAX_REQUEST_BYTES=4)
    with TestClient(tap.app) as client:
        response = client.post("/legacy/frames", content=b"12345")
    assert response.status_code == 413
    assert calls == 0


def test_tap_rejects_oversized_upstream_response(tmp_path, monkeypatch):
    async def handler(request):
        return httpx.Response(200, content=b"12345")

    tap = _tap(tmp_path, monkeypatch, handler, MAX_RESPONSE_BYTES=4)
    with TestClient(tap.app) as client:
        response = client.get("/readyz")
    assert response.status_code == 502


def test_tap_rejects_compression_before_decoding(tmp_path, monkeypatch):
    async def handler(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            content=gzip.compress(b"secret"),
        )

    tap = _tap(tmp_path, monkeypatch, handler)
    with TestClient(tap.app) as client:
        response = client.get("/readyz")
    assert response.status_code == 502
    assert "compressed" in response.text


def test_tap_enforces_total_relay_deadline(tmp_path, monkeypatch):
    async def handler(request):
        import asyncio

        await asyncio.sleep(0.05)
        return httpx.Response(200, content=b"late")

    tap = _tap(tmp_path, monkeypatch, handler, RELAY_DEADLINE_SECONDS=0.01)
    started = time.monotonic()
    with TestClient(tap.app) as client:
        response = client.get("/readyz")
    assert response.status_code == 502
    assert time.monotonic() - started < 1


def test_tap_stops_recording_at_storage_cap_but_keeps_relaying(tmp_path, monkeypatch):
    async def handler(request):
        return httpx.Response(200, content=b"ok")

    tap = _tap(tmp_path, monkeypatch, handler, CAPTURE_MAX_BYTES=1)
    with TestClient(tap.app) as client:
        assert client.get("/one").status_code == 200
        assert client.get("/two").status_code == 200
        health = client.get("/tap/healthz").json()
    assert health["capture_dropped"] == 2
    assert health["capture_bytes"] == 0


def test_tap_truncates_recorded_raw_fields(tmp_path, monkeypatch):
    async def handler(request):
        return httpx.Response(200, content=b"response-is-long")

    tap = _tap(tmp_path, monkeypatch, handler, CAPTURE_FIELD_BYTES=8)
    with TestClient(tap.app) as client:
        assert client.post("/opaque", content=b"request-is-long").status_code == 200

    entry = json.loads((tmp_path / "capture.jsonl").read_text().strip())
    assert entry["request_json"] is None
    assert entry["request_raw"].endswith("...[truncated]")
    assert entry["response_raw"].endswith("...[truncated]")
