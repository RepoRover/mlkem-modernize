"""End-to-end tests over the real service applications.

These run in-process rather than under Docker: the gateway's HTTP client is
pointed at the cloud application through an ASGI transport, so the genuine
request handling, session storage, and persistence code all execute. That
keeps the feedback loop fast enough for CI while still covering the paths that
only appear when the services talk to each other.
"""

import importlib

import pytest
from fastapi.testclient import TestClient

import pqcsuite as cs
from pqcwire.protocol import HYBRID_PQC, LEGACY_RSA
from pqcwire.telemetry import WeatherReading

READINGS = [
    WeatherReading("2024-01-01", 7.4, 3.4, 1.8, 19.7),
    WeatherReading("2024-01-02", 7.0, 2.5, 7.2, 20.2),
    WeatherReading("2024-01-03", 10.6, 7.3, 12.1, 27.8),
]


def _build_cloud(tmp_path, monkeypatch, allow_legacy: bool):
    monkeypatch.setenv("CLOUD_DB_PATH", str(tmp_path / "readings.db"))
    monkeypatch.setenv("CLOUD_KEY_PATH", str(tmp_path / "cloud_rsa.pem"))
    monkeypatch.setenv("CLOUD_IDENTITY_PATH", str(tmp_path / "cloud_mldsa.key"))
    monkeypatch.setenv("ALLOW_LEGACY_SUITE", "true" if allow_legacy else "false")

    import services.cloud.app as cloud_module

    importlib.reload(cloud_module)
    return cloud_module.app


def _build_gateway(tmp_path, monkeypatch, cloud_app, upstream_suite: str):
    monkeypatch.setenv("GATEWAY_KEY_PATH", str(tmp_path / "gateway_rsa.pem"))
    monkeypatch.setenv("CLOUD_URL", "http://cloud")
    monkeypatch.setenv("UPSTREAM_SUITE", upstream_suite)

    import services.gateway.app as gateway_module

    importlib.reload(gateway_module)
    # Route the gateway's upstream calls into the cloud application directly.
    # TestClient is a synchronous httpx client that speaks ASGI, which matches
    # the gateway's own sync client; httpx.ASGITransport is async-only and
    # cannot be used here.
    gateway_module._upstream._client = TestClient(cloud_app, base_url="http://cloud")
    return gateway_module.app


def _send_readings(gateway_client: TestClient) -> str:
    """Drive the device half of the protocol against the gateway."""
    pem = gateway_client.get("/legacy/pubkey").content
    client = cs.LegacyClient(cs.load_public_key(pem))
    request, session = client.open_session()

    response = gateway_client.post("/legacy/session", json=request.to_dict())
    assert response.status_code == 200, response.text

    for reading in READINGS:
        frame = session.seal(reading.to_json().encode())
        response = gateway_client.post("/legacy/frames", json=frame.to_dict())
        assert response.status_code == 200, response.text
    return request.session_id


@pytest.mark.parametrize(
    ("upstream_suite", "expected_suite", "allow_legacy"),
    [
        pytest.param("legacy", LEGACY_RSA, True, id="baseline"),
        pytest.param("hybrid", HYBRID_PQC, False, id="modernized"),
    ],
)
def test_readings_reach_the_cloud_over_the_configured_suite(
    tmp_path, monkeypatch, upstream_suite, expected_suite, allow_legacy
):
    """The device is unchanged in both cases; only the upstream link differs."""
    cloud_app = _build_cloud(tmp_path, monkeypatch, allow_legacy)
    gateway_app = _build_gateway(tmp_path, monkeypatch, cloud_app, upstream_suite)

    with TestClient(cloud_app) as cloud, TestClient(gateway_app) as gateway:
        _send_readings(gateway)

        stored = cloud.get("/readings?limit=10").json()
        assert stored["total"] == len(READINGS)
        assert stored["by_suite"] == {expected_suite: len(READINGS)}

        dates = {row["date"] for row in stored["readings"]}
        assert dates == {reading.date for reading in READINGS}


def test_gateway_reports_that_it_is_brokering_between_suites(tmp_path, monkeypatch):
    cloud_app = _build_cloud(tmp_path, monkeypatch, allow_legacy=False)
    gateway_app = _build_gateway(tmp_path, monkeypatch, cloud_app, "hybrid")

    with TestClient(gateway_app) as gateway:
        report = gateway.get("/capabilities").json()

    assert report["downstream_suite"] == LEGACY_RSA
    assert report["upstream_suite"] == HYBRID_PQC
    assert report["brokering"] is True


def test_cloud_refuses_legacy_traffic_once_the_migration_completes(tmp_path, monkeypatch):
    cloud_app = _build_cloud(tmp_path, monkeypatch, allow_legacy=False)

    with TestClient(cloud_app) as cloud:
        assert cloud.get("/legacy/pubkey").status_code == 403
        assert cloud.post("/legacy/session", json={}).status_code == 403
        # The post-quantum path is unaffected.
        assert cloud.get("/pqc/offer").status_code == 200
        assert cloud.get("/capabilities").json()["accepted_suites"] == [HYBRID_PQC]


def test_health_and_readiness_probes_respond(tmp_path, monkeypatch):
    cloud_app = _build_cloud(tmp_path, monkeypatch, allow_legacy=True)
    gateway_app = _build_gateway(tmp_path, monkeypatch, cloud_app, "legacy")

    with TestClient(cloud_app) as cloud, TestClient(gateway_app) as gateway:
        assert cloud.get("/healthz").json()["status"] == "ok"
        assert cloud.get("/readyz").json()["status"] == "ready"
        assert gateway.get("/healthz").json()["status"] == "ok"
        assert gateway.get("/readyz").json()["status"] == "ready"


def test_a_replayed_frame_is_refused_by_the_gateway(tmp_path, monkeypatch):
    cloud_app = _build_cloud(tmp_path, monkeypatch, allow_legacy=True)
    gateway_app = _build_gateway(tmp_path, monkeypatch, cloud_app, "legacy")

    with TestClient(cloud_app), TestClient(gateway_app) as gateway:
        pem = gateway.get("/legacy/pubkey").content
        client = cs.LegacyClient(cs.load_public_key(pem))
        request, session = client.open_session()
        gateway.post("/legacy/session", json=request.to_dict())

        frame = session.seal(b'{"date":"2024-01-01"}')
        assert gateway.post("/legacy/frames", json=frame.to_dict()).status_code == 200
        assert gateway.post("/legacy/frames", json=frame.to_dict()).status_code == 400


def test_frames_for_an_unknown_session_are_refused(tmp_path, monkeypatch):
    cloud_app = _build_cloud(tmp_path, monkeypatch, allow_legacy=True)
    gateway_app = _build_gateway(tmp_path, monkeypatch, cloud_app, "legacy")

    with TestClient(cloud_app), TestClient(gateway_app) as gateway:
        pem = gateway.get("/legacy/pubkey").content
        _, session = cs.LegacyClient(cs.load_public_key(pem)).open_session()
        orphan = session.seal(b'{"date":"2024-01-01"}')
        assert gateway.post("/legacy/frames", json=orphan.to_dict()).status_code == 409
