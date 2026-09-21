"""Session lifetime, rekeying, and the 'never log secrets' rule."""

from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from services.cloud.main import create_app as create_cloud_app
from services.common import cryptoutil as cu
from services.common.config import setup_logging
from services.common.sessions import ServerSession, SessionStore, iso, utc_now
from services.common.wire import b64e
from services.gateway.cloud_client import CloudClient
from services.gateway.main import create_app as create_gateway_app

DEVICE_ID = "device-berlin-01"


def _session(store: SessionStore, **overrides) -> ServerSession:
    defaults: dict[str, Any] = dict(
        session_id=cu.random_bytes(16),
        client_id=DEVICE_ID,
        receiver=cu.AeadReceiver(cu.random_bytes(32), b"s" * 16, b"p" * 4),
        expires_at=store.new_expiry(),
        max_records=store.max_records,
    )
    return ServerSession(**{**defaults, **overrides})


# ------------------------------------------------------------ session store


def test_session_is_retrievable_until_it_expires():
    store = SessionStore(ttl_seconds=600, max_records=100)
    session = _session(store)
    store.put(session)

    assert store.get(session.session_id) is session
    assert store.active == 1


def test_session_expires_on_time():
    store = SessionStore(ttl_seconds=600, max_records=100)
    session = _session(store, expires_at=utc_now() - timedelta(seconds=1))
    store.put(session)

    assert store.get(session.session_id) is None
    # Expired sessions are dropped on access, not left to accumulate.
    assert store.active == 0


def test_session_expires_on_record_budget():
    store = SessionStore(ttl_seconds=600, max_records=3)
    session = _session(store)
    store.put(session)

    session.accepted = 3
    assert session.is_expired()
    assert store.get(session.session_id) is None


def test_prune_removes_only_expired_sessions():
    store = SessionStore(ttl_seconds=600, max_records=100)
    live = _session(store)
    dead = _session(store, expires_at=utc_now() - timedelta(seconds=1))
    store.put(live)
    store.put(dead)

    assert store.prune() == 1
    assert store.active == 1
    assert store.get(live.session_id) is live


def test_unknown_session_id_returns_none():
    store = SessionStore(ttl_seconds=600, max_records=100)
    assert store.get(cu.random_bytes(16)) is None


def test_handshake_nonce_is_remembered_once():
    store = SessionStore(ttl_seconds=600, max_records=100)
    nonce = cu.random_bytes(16)

    assert store.remember_nonce(nonce) is True
    assert store.remember_nonce(nonce) is False
    assert store.remember_nonce(cu.random_bytes(16)) is True


def test_nonce_table_is_pruned_so_it_cannot_grow_without_bound(monkeypatch):
    """Otherwise a long-running gateway leaks memory one nonce per handshake."""
    import services.common.sessions as sessions_module

    clock = {"now": 1000.0}
    monkeypatch.setattr(sessions_module.time, "monotonic", lambda: clock["now"])

    store = SessionStore(ttl_seconds=60, max_records=100)
    old = cu.random_bytes(16)
    store.remember_nonce(old)

    # Move past 2 * ttl, then touch the table.
    clock["now"] += 200.0
    store.remember_nonce(cu.random_bytes(16))

    # The old nonce has aged out -- which also means a very old ClientHello
    # becomes replayable again. Documented limit, not an accident.
    assert store.remember_nonce(old) is True


def test_iso_is_utc_with_a_trailing_z():
    stamp = iso(utc_now())
    assert stamp.endswith("Z")
    assert len(stamp) == 20  # YYYY-MM-DDTHH:MM:SSZ


# ------------------------------------------------------------ rekey in situ


@pytest.fixture()
def stack_with_budget(keys_dir: Path):
    def build(max_records: int):
        cloud_app = create_cloud_app(
            keys_dir=str(keys_dir), db_path=":memory:", max_records=max_records
        )
        cloud_http = TestClient(cloud_app, base_url="http://cloud")
        cloud_client = CloudClient(
            base_url="http://cloud",
            gateway_id="gw-01",
            signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
            cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
            log=logging.getLogger("test"),
            http_client=cloud_http,
        )
        gateway_app = create_gateway_app(
            keys_dir=str(keys_dir),
            cloud_url="http://cloud",
            max_records=max_records,
            cloud_client=cloud_client,
        )
        gateway_http = TestClient(gateway_app, base_url="http://gateway")
        return gateway_http, cloud_http

    return build


def test_client_rekeys_when_the_record_budget_runs_out(stack_with_budget, keys_dir: Path):
    from services.device.gateway_client import GatewayClient

    gateway_http, cloud_http = stack_with_budget(2)
    device = GatewayClient(
        base_url="http://gateway",
        device_id=DEVICE_ID,
        device_static_key=cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
        gateway_public_key=cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
        log=logging.getLogger("test"),
        http_client=gateway_http,
    )

    for day in range(1, 8):
        payload = {
            "device_id": DEVICE_ID,
            "date": f"2024-01-{day:02d}",
            "temp_max_c": 7.4, "temp_min_c": 3.4,
            "precip_mm": 1.8, "wind_max_kmh": 19.7,
        }
        assert device.send_reading(payload)["status"] == "accepted"

    # 7 readings with a 2-record budget means at least 4 sessions on each hop.
    assert gateway_http.get("/stats").json()["messages"]["handshakes"] >= 4
    assert cloud_http.get("/stats").json()["messages"]["handshakes"] >= 4
    assert cloud_http.get("/stats").json()["storage"]["total"] == 7

    device.close()
    gateway_http.close()
    cloud_http.close()


def test_expired_session_is_refused_and_the_client_recovers(stack_with_budget):
    """A stale session_id must be refused with session_expired, not accepted."""
    gateway_http, _ = stack_with_budget(100)

    hello = gateway_http.post(
        "/handshake",
        json={
            "protocol": "wx-legacy/1",
            "hop": "device-gateway",
            "client_id": DEVICE_ID,
            "client_nonce": b64e(cu.random_bytes(16)),
        },
    ).json()

    # Force expiry the way the TTL would.
    store = gateway_http.app.state.sessions
    for session in list(store._sessions.values()):
        session.expires_at = utc_now() - timedelta(seconds=1)

    response = gateway_http.post(
        "/ingest",
        json={
            "session_id": hello["session_id"],
            "seq": 0,
            "nonce": b64e(cu.random_bytes(12)),
            "ct": b64e(cu.random_bytes(32)),
        },
    )
    assert response.status_code == 409
    assert response.json()["reason"] == "session_expired"

    # A fresh handshake still works afterwards.
    assert gateway_http.post(
        "/handshake",
        json={
            "protocol": "wx-legacy/1",
            "hop": "device-gateway",
            "client_id": DEVICE_ID,
            "client_nonce": b64e(cu.random_bytes(16)),
        },
    ).status_code == 200

    gateway_http.close()


# ------------------------------------------------- never log key material


def test_derived_session_repr_hides_the_key():
    from services.common.handshake import DerivedSession

    key = cu.random_bytes(32)
    session = DerivedSession(cu.random_bytes(16), cu.random_bytes(4), key)

    assert key.hex() not in repr(session)
    assert "redacted" in repr(session)


def test_handshake_logs_do_not_contain_key_material(keys_dir: Path, caplog):
    """Scan everything the services log during a real exchange.

    This is a smoke test, not a proof: it can only catch secrets that happen to
    appear in this run's log lines. See docs/TESTING.md on why 'no secret is
    ever logged' is not fully testable.
    """
    from services.common.handshake import hop1_derive
    from services.common.wire import b64d

    cloud_app = create_cloud_app(keys_dir=str(keys_dir), db_path=":memory:")
    cloud_http = TestClient(cloud_app, base_url="http://cloud")
    cloud_client = CloudClient(
        base_url="http://cloud", gateway_id="gw-01",
        signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
        cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        log=logging.getLogger("test"), http_client=cloud_http,
    )
    gateway_app = create_gateway_app(
        keys_dir=str(keys_dir), cloud_url="http://cloud", cloud_client=cloud_client
    )
    gateway_http = TestClient(gateway_app, base_url="http://gateway")

    with caplog.at_level(logging.DEBUG):
        client_nonce = cu.random_bytes(16)
        hello = gateway_http.post(
            "/handshake",
            json={
                "protocol": "wx-legacy/1", "hop": "device-gateway",
                "client_id": DEVICE_ID, "client_nonce": b64e(client_nonce),
            },
        ).json()

        derived = hop1_derive(
            cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
            cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
            client_nonce, b64d(hello["server_nonce"]),
            b64d(hello["session_id"]), b64d(hello["nonce_prefix"]),
        )
        sender = cu.AeadSender(derived.key, b64d(hello["session_id"]),
                               b64d(hello["nonce_prefix"]))
        seq, nonce, ct = sender.encrypt(
            b'{"device_id":"device-berlin-01","date":"2024-01-01",'
            b'"temp_max_c":7.4,"temp_min_c":3.4,"precip_mm":1.8,"wind_max_kmh":19.7}'
        )
        gateway_http.post("/ingest", json={
            "session_id": hello["session_id"], "seq": seq,
            "nonce": b64e(nonce), "ct": b64e(ct),
        })

    logs = "\n".join(record.getMessage() for record in caplog.records)

    # The session key must appear in no encoding we might plausibly have used.
    assert derived.key.hex() not in logs
    assert b64e(derived.key) not in logs
    assert str(list(derived.key)) not in logs

    # Nor may the long-term private keys.
    private_pem = (keys_dir / "device_ecdh_priv.pem").read_text()
    for line in private_pem.splitlines():
        if line and "-----" not in line:
            assert line not in logs

    gateway_http.close()
    cloud_http.close()


def test_logging_setup_uses_utc(monkeypatch):
    """Log timestamps must match the ISO fields on the wire, which are UTC."""
    import time as time_module

    setup_logging("test-service")
    assert logging.Formatter.converter is time_module.gmtime
