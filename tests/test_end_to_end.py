"""Device -> gateway -> cloud, wired together in-process.

No Docker and no sockets: both FastAPI apps are driven through Starlette's
TestClient, which is an httpx.Client subclass, so it drops straight into the
same injection point the real services use. Runs in CI and on a laptop alike.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from services.cloud.main import create_app as create_cloud_app
from services.common import cryptoutil as cu
from services.common.wire import b64e
from services.device.gateway_client import GatewayClient
from services.gateway.cloud_client import CloudClient
from services.gateway.main import create_app as create_gateway_app

from .conftest import DATA_FILE

log = logging.getLogger("test")

DEVICE_ID = "device-berlin-01"


@pytest.fixture()
def stack(keys_dir: Path):
    """Build cloud + gateway + device client, all talking in-process."""
    cloud_app = create_cloud_app(keys_dir=str(keys_dir), db_path=":memory:")
    cloud_http = TestClient(cloud_app, base_url="http://cloud")

    cloud_client = CloudClient(
        base_url="http://cloud",
        gateway_id="gw-01",
        signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
        cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        log=log,
        http_client=cloud_http,
    )

    gateway_app = create_gateway_app(
        keys_dir=str(keys_dir),
        cloud_url="http://cloud",
        cloud_client=cloud_client,
    )
    gateway_http = TestClient(gateway_app, base_url="http://gateway")

    device = GatewayClient(
        base_url="http://gateway",
        device_id=DEVICE_ID,
        device_static_key=cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
        gateway_public_key=cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
        log=log,
        http_client=gateway_http,
    )

    yield device, gateway_http, cloud_http

    device.close()
    gateway_http.close()
    cloud_http.close()


def _reading(date: str = "2024-01-01") -> dict:
    return {
        "device_id": DEVICE_ID,
        "station": {"lat": 52.54833, "lon": 13.407822, "elev_m": 38.0, "tz": "Europe/Berlin"},
        "sent_at": "2026-09-21T10:00:00Z",
        "date": date,
        "temp_max_c": 7.4,
        "temp_min_c": 3.4,
        "precip_mm": 1.8,
        "wind_max_kmh": 19.7,
    }


def test_reading_travels_both_hops_and_is_readable(stack):
    device, _, cloud_http = stack

    result = device.send_reading(_reading())
    assert result["status"] == "accepted"
    assert result["cloud"] == "accepted"

    response = cloud_http.get("/readings")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1

    stored = body["readings"][0]
    assert stored["date"] == "2024-01-01"
    assert stored["device_id"] == DEVICE_ID
    assert stored["gateway_id"] == "gw-01"
    assert stored["temp_max_c"] == pytest.approx(7.4)


def test_many_readings_including_a_forced_rekey(keys_dir: Path):
    """max_records=3 forces several handshakes over 10 readings."""
    cloud_app = create_cloud_app(keys_dir=str(keys_dir), db_path=":memory:", max_records=3)
    cloud_http = TestClient(cloud_app, base_url="http://cloud")
    cloud_client = CloudClient(
        base_url="http://cloud",
        gateway_id="gw-01",
        signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
        cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        log=log,
        http_client=cloud_http,
    )
    gateway_app = create_gateway_app(
        keys_dir=str(keys_dir), cloud_url="http://cloud",
        max_records=3, cloud_client=cloud_client,
    )
    gateway_http = TestClient(gateway_app, base_url="http://gateway")
    device = GatewayClient(
        base_url="http://gateway", device_id=DEVICE_ID,
        device_static_key=cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
        gateway_public_key=cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
        log=log, http_client=gateway_http,
    )

    dates = [f"2024-01-{day:02d}" for day in range(1, 11)]
    for date in dates:
        assert device.send_reading(_reading(date))["status"] == "accepted"

    stats = cloud_http.get("/stats").json()
    assert stats["storage"]["total"] == 10
    # 10 readings with a 3-record budget means at least 4 sessions per hop.
    assert stats["messages"]["handshakes"] >= 4
    assert gateway_http.get("/stats").json()["messages"]["handshakes"] >= 4

    device.close()
    gateway_http.close()
    cloud_http.close()


def test_replaying_a_date_updates_rather_than_duplicates(stack):
    device, _, cloud_http = stack

    assert device.send_reading(_reading("2024-03-01"))["status"] == "accepted"
    warmer = {**_reading("2024-03-01"), "temp_max_c": 12.5}
    assert device.send_reading(warmer)["status"] == "accepted"

    body = cloud_http.get("/readings").json()
    assert body["count"] == 1
    assert body["readings"][0]["temp_max_c"] == pytest.approx(12.5)


def test_gateway_rejects_an_implausible_reading(stack):
    device, gateway_http, cloud_http = stack

    bad = {**_reading(), "temp_max_c": 500.0}
    result = device.send_reading(bad)

    assert result["status"] == "rejected"
    assert result["reason"] == "validation_failed"
    # Nothing reached the cloud.
    assert cloud_http.get("/readings").json()["count"] == 0
    assert gateway_http.get("/stats").json()["messages"]["rejected"] == 1


def test_gateway_rejects_a_device_id_that_does_not_match_the_session(stack):
    device, _, cloud_http = stack

    spoofed = {**_reading(), "device_id": "device-somewhere-else"}
    result = device.send_reading(spoofed)

    assert result["status"] == "rejected"
    assert result["reason"] == "device_id_mismatch"
    assert cloud_http.get("/readings").json()["count"] == 0


def test_gateway_rejects_an_unknown_device(keys_dir: Path, stack):
    _, gateway_http, _ = stack

    response = gateway_http.post(
        "/handshake",
        json={
            "protocol": "wx-legacy/1",
            "hop": "device-gateway",
            "client_id": "not-registered",
            "client_nonce": b64e(cu.random_bytes(16)),
        },
    )
    assert response.status_code == 403


def test_gateway_rejects_a_replayed_client_hello(stack):
    _, gateway_http, _ = stack

    hello = {
        "protocol": "wx-legacy/1",
        "hop": "device-gateway",
        "client_id": DEVICE_ID,
        "client_nonce": b64e(cu.random_bytes(16)),
    }
    assert gateway_http.post("/handshake", json=hello).status_code == 200
    # Same nonce again: a captured ClientHello must not open a second session.
    assert gateway_http.post("/handshake", json=hello).status_code == 409


def test_cloud_rejects_a_forged_gateway_signature(keys_dir: Path):
    """Hop 2 authenticates the gateway explicitly, unlike hop 1."""
    cloud_app = create_cloud_app(keys_dir=str(keys_dir), db_path=":memory:")
    cloud_http = TestClient(cloud_app, base_url="http://cloud")

    impostor = cu.generate_private_key()
    eph = cu.generate_private_key()
    nonce = cu.random_bytes(16)
    eph_pub = cu.public_key_to_bytes(eph.public_key())

    from services.common.handshake import hop2_client_transcript

    transcript = hop2_client_transcript("gw-01", nonce, eph_pub)
    response = cloud_http.post(
        "/handshake",
        json={
            "protocol": "wx-legacy/1",
            "hop": "gateway-cloud",
            "client_id": "gw-01",
            "client_nonce": b64e(nonce),
            "eph_pub": b64e(eph_pub),
            "sig": b64e(cu.sign(impostor, transcript)),
        },
    )
    assert response.status_code == 403
    cloud_http.close()


def test_gateway_rejects_a_tampered_ciphertext(keys_dir: Path, stack):
    """A flipped bit on hop 1 must fail the AEAD tag, not be stored."""
    import json

    from services.common.handshake import hop1_derive

    _, gateway_http, cloud_http = stack

    # Run a hop 1 handshake by hand so we can corrupt the message afterwards.
    client_nonce = cu.random_bytes(16)
    hello = gateway_http.post(
        "/handshake",
        json={
            "protocol": "wx-legacy/1",
            "hop": "device-gateway",
            "client_id": DEVICE_ID,
            "client_nonce": b64e(client_nonce),
        },
    ).json()

    from services.common.wire import b64d

    session_id = b64d(hello["session_id"])
    derived = hop1_derive(
        cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
        cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
        client_nonce,
        b64d(hello["server_nonce"]),
        session_id,
        b64d(hello["nonce_prefix"]),
    )
    sender = cu.AeadSender(derived.key, session_id, derived.nonce_prefix)
    seq, nonce, ciphertext = sender.encrypt(json.dumps(_reading()).encode())

    tampered = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    response = gateway_http.post(
        "/ingest",
        json={
            "session_id": b64e(session_id),
            "seq": seq,
            "nonce": b64e(nonce),
            "ct": b64e(tampered),
        },
    )

    assert response.status_code == 400
    assert response.json()["reason"] == "bad_tag"
    assert cloud_http.get("/readings").json()["count"] == 0

    # The intact message still works, proving the handshake itself was fine.
    ok = gateway_http.post(
        "/ingest",
        json={
            "session_id": b64e(session_id),
            "seq": seq,
            "nonce": b64e(nonce),
            "ct": b64e(ciphertext),
        },
    )
    assert ok.json()["status"] == "accepted"


def test_full_dataset_first_slice_flows_through(stack):
    """Sanity check against the real file rather than a hand-written payload."""
    from services.common.weather import parse_weather_file

    device, _, cloud_http = stack
    station, readings = parse_weather_file(DATA_FILE)

    for reading in readings[:5]:
        payload = {
            "device_id": DEVICE_ID,
            "station": station.to_dict(),
            "sent_at": "2026-09-21T10:00:00Z",
            **reading.to_dict(),
        }
        assert device.send_reading(payload)["status"] == "accepted"

    body = cloud_http.get("/readings").json()
    assert body["count"] == 5
    assert {r["date"] for r in body["readings"]} == {r.date for r in readings[:5]}


def test_read_api_surface(stack):
    device, _, cloud_http = stack
    device.send_reading(_reading("2024-05-05"))

    assert cloud_http.get("/health").json()["status"] == "ok"
    assert cloud_http.get("/readings/2024-05-05").json()["count"] == 1
    assert cloud_http.get("/readings/1999-01-01").status_code == 404
    assert cloud_http.get("/readings?since=2024-06-01").json()["count"] == 0
    assert cloud_http.get("/readings?since=2024-01-01").json()["count"] == 1
