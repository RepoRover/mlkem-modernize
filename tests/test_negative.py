"""Negative tests: everything hostile or malformed must be REJECTED, not crash.

The contract this module enforces:

  * the service returns a structured rejection with a reason code,
  * it never returns 5xx (that would mean an unhandled exception),
  * it never stores anything,
  * it stays alive and serves the next request normally.

The last point matters most. A service that rejects an attack and then falls
over has still been denied-of-service, so almost every test here sends a good
message afterwards and asserts it is accepted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from services.cloud.main import create_app as create_cloud_app
from services.common import cryptoutil as cu
from services.common.handshake import hop1_derive
from services.common.weather import (
    ValidationError,
    WeatherDataError,
    parse_weather_text,
    validate_reading,
)
from services.common.wire import PROTOCOL_V2, b64d, b64e
from services.gateway.cloud_client import CloudClient
from services.gateway.main import create_app as create_gateway_app

DEVICE_ID = "device-berlin-01"
PROTOCOL = "wx-legacy/1"


# ---------------------------------------------------------------- fixtures


@pytest.fixture()
def gw(keys_dir: Path):
    """Gateway + cloud, with a raw hop 1 session we control byte by byte."""
    cloud_app = create_cloud_app(keys_dir=str(keys_dir), db_path=":memory:")
    cloud_http = TestClient(cloud_app, base_url="http://cloud")
    cloud_client = CloudClient(
        base_url="http://cloud",
        gateway_id="gw-01",
        signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
        cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        log=__import__("logging").getLogger("test"),
        http_client=cloud_http,
    )
    gateway_app = create_gateway_app(
        keys_dir=str(keys_dir), cloud_url="http://cloud", cloud_client=cloud_client
    )
    gateway_http = TestClient(gateway_app, base_url="http://gateway")

    yield gateway_http, cloud_http, keys_dir

    gateway_http.close()
    cloud_http.close()


class Hop1Session:
    """A hand-driven hop 1 client so tests can corrupt individual fields."""

    def __init__(self, gateway_http: TestClient, keys_dir: Path,
                 device_key=None, gateway_pub=None):
        self.http = gateway_http
        nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        hello = gateway_http.post(
            "/handshake",
            json={
                "protocol": PROTOCOL,
                "hop": "device-gateway",
                "client_id": DEVICE_ID,
                "client_nonce": b64e(nonce),
            },
        )
        assert hello.status_code == 200
        body = hello.json()

        self.session_id = b64d(body["session_id"])
        self.prefix = b64d(body["nonce_prefix"])
        derived = hop1_derive(
            device_key or cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
            gateway_pub or cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
            nonce,
            b64d(body["server_nonce"]),
            self.session_id,
            self.prefix,
        )
        self.sender = cu.AeadSender(derived.key, self.session_id, self.prefix)

    def seal(self, payload: dict):
        return self.sender.encrypt(json.dumps(payload).encode())

    def post(self, seq: int, nonce: bytes, ct: bytes):
        return self.http.post(
            "/ingest",
            json={
                "session_id": b64e(self.session_id),
                "seq": seq,
                "nonce": b64e(nonce),
                "ct": b64e(ct),
            },
        )

    def send(self, payload: dict):
        return self.post(*self.seal(payload))


class Hop2Session:
    """A hand-driven hop 2 v2 client, so the cloud's reject paths can be hit directly.

    Speaks the hybrid PQC handshake, because that is now the default path. The
    classical fallback is exercised separately in tests/test_pqc.py.
    """

    def __init__(self, cloud_http: TestClient, keys_dir: Path, signing_key=None):
        from services.common.handshake import (
            KeyShare,
            hop2_v2_client_transcript,
            hop2_v2_derive,
            hop2_v2_server_transcript,
        )
        from services.common.suites import SUITE_HYBRID

        self.http = cloud_http
        signing_key = signing_key or cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")

        nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        x_priv = cu.generate_x25519_private_key()
        x_pub = cu.x25519_public_bytes(x_priv.public_key())
        kem_priv = cu.generate_mlkem768_private_key()
        ek = cu.mlkem768_encapsulation_key_bytes(kem_priv)

        offered = [SUITE_HYBRID]
        shares = {SUITE_HYBRID: KeyShare(x25519_pub=x_pub, mlkem768_ek=ek)}

        hello = cloud_http.post(
            "/handshake",
            json={
                "protocol": PROTOCOL_V2,
                "hop": "gateway-cloud",
                "client_id": "gw-01",
                "client_nonce": b64e(nonce),
                "offered_suites": offered,
                "key_shares": {
                    SUITE_HYBRID: {"x25519_pub": b64e(x_pub), "mlkem768_ek": b64e(ek)}
                },
                "sig": b64e(
                    cu.sign(
                        signing_key,
                        hop2_v2_client_transcript("gw-01", nonce, offered, shares),
                    )
                ),
            },
        )
        assert hello.status_code == 200, hello.text
        body = hello.json()
        assert body["selected_suite"] == SUITE_HYBRID

        self.session_id = b64d(body["session_id"])
        self.prefix = b64d(body["nonce_prefix"])
        server_x_pub = b64d(body["x25519_pub"])
        self.mlkem_ct = b64d(body["mlkem768_ct"])
        server_share = KeyShare(x25519_pub=server_x_pub)

        # Verify the server signature, exactly as the real gateway does.
        transcript = hop2_v2_server_transcript(
            client_id="gw-01", client_nonce=nonce, offered_suites=offered,
            client_shares=shares, selected_suite=SUITE_HYBRID,
            session_id=self.session_id, server_nonce=b64d(body["server_nonce"]),
            server_share=server_share, mlkem768_ct=self.mlkem_ct,
            nonce_prefix=self.prefix, expires_at=body["expires_at"],
            max_records=int(body["max_records"]),
        )
        assert cu.verify(
            cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
            b64d(body["sig"]), transcript,
        )

        derived = hop2_v2_derive(
            selected_suite=SUITE_HYBRID,
            ss_mlkem768=cu.mlkem768_decapsulate(kem_priv, self.mlkem_ct),
            ss_classical=cu.x25519_exchange(x_priv, cu.x25519_public_from_bytes(server_x_pub)),
            client_id="gw-01", offered_suites=offered,
            client_nonce=nonce, server_nonce=b64d(body["server_nonce"]),
            client_share=shares[SUITE_HYBRID], server_share=server_share,
            mlkem768_ct=self.mlkem_ct,
            session_id=self.session_id, nonce_prefix=self.prefix,
        )
        # We SEND on the client->server key.
        self.sender = cu.AeadSender(derived.key_c2s, self.session_id, self.prefix)

    def seal(self, envelope: dict):
        return self.sender.encrypt(json.dumps(envelope).encode())

    def post(self, seq: int, nonce: bytes, ct: bytes):
        return self.http.post(
            "/ingest",
            json={
                "session_id": b64e(self.session_id),
                "seq": seq,
                "nonce": b64e(nonce),
                "ct": b64e(ct),
            },
        )

    def send(self, envelope: dict):
        return self.post(*self.seal(envelope))


def envelope(date: str = "2024-01-01", **overrides) -> dict:
    base = {
        "gateway_id": "gw-01",
        "device_id": DEVICE_ID,
        "reading": {
            "date": date,
            "temp_max_c": 7.4,
            "temp_min_c": 3.4,
            "precip_mm": 1.8,
            "wind_max_kmh": 19.7,
        },
        "received_at": "2026-09-21T10:00:02Z",
        "device_hop": {"verified": True, "suite": "ECDH-P256-static-static+AES-256-GCM"},
    }
    base.update(overrides)
    return base


def reading(date: str = "2024-01-01") -> dict:
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


def assert_rejected(response, reason: str | None = None) -> None:
    """A rejection is a 4xx with a reason -- never a 5xx, never a crash."""
    assert 400 <= response.status_code < 500, (
        f"expected a 4xx rejection, got {response.status_code}: {response.text[:200]}"
    )
    body = response.json()
    assert body.get("status") in {"rejected", None} or "detail" in body
    if reason is not None:
        assert body.get("reason") == reason, f"expected reason={reason}, got {body}"


# ------------------------------------------------------- tampered ciphertext


@pytest.mark.parametrize("position", [0, 7, -17, -1])
def test_tampered_ciphertext_is_rejected_at_every_position(gw, position):
    """Flipping a bit anywhere -- body, tag, boundary -- must fail the tag."""
    gateway_http, cloud_http, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    seq, nonce, ct = session.seal(reading())
    tampered = bytearray(ct)
    tampered[position] ^= 0x01

    response = session.post(seq, nonce, bytes(tampered))
    assert_rejected(response, "bad_tag")
    assert cloud_http.get("/readings").json()["count"] == 0

    # Service survives and the intact message still works.
    assert session.post(seq, nonce, ct).json()["status"] == "accepted"


def test_truncated_ciphertext_is_rejected(gw):
    gateway_http, cloud_http, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)
    seq, nonce, ct = session.seal(reading())

    assert_rejected(session.post(seq, nonce, ct[:-4]), "bad_tag")
    # Shorter than the GCM tag itself -- must not raise anything unhandled.
    assert_rejected(session.post(seq, nonce, b"\x00" * 4), "bad_tag")
    assert_rejected(session.post(seq, nonce, b""), "bad_tag")
    assert cloud_http.get("/readings").json()["count"] == 0


def test_ciphertext_from_a_different_session_is_rejected(gw):
    """A valid ciphertext cannot be moved between sessions: the AAD binds it."""
    gateway_http, cloud_http, keys_dir = gw
    victim = Hop1Session(gateway_http, keys_dir)
    attacker = Hop1Session(gateway_http, keys_dir)

    seq, _, ct = attacker.seal(reading())
    # Replay it into the victim session, using the victim's own nonce.
    victim_nonce = victim.prefix + b"\x00" * 7 + bytes([seq])
    assert_rejected(victim.post(seq, victim_nonce, ct), "bad_tag")
    assert cloud_http.get("/readings").json()["count"] == 0


# ---------------------------------------------------------- replayed message


def test_replayed_message_is_rejected(gw):
    gateway_http, cloud_http, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    seq, nonce, ct = session.seal(reading())
    assert session.post(seq, nonce, ct).json()["status"] == "accepted"

    # Byte-identical replay.
    assert_rejected(session.post(seq, nonce, ct), "replay")
    # Still exactly one stored record.
    assert cloud_http.get("/readings").json()["count"] == 1


def test_out_of_order_message_is_rejected(gw):
    gateway_http, _, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    first = session.seal(reading("2024-01-01"))
    second = session.seal(reading("2024-01-02"))

    assert session.post(*second).json()["status"] == "accepted"
    assert_rejected(session.post(*first), "replay")


def test_replayed_client_hello_cannot_open_a_second_session(gw):
    gateway_http, _, _ = gw
    hello = {
        "protocol": PROTOCOL,
        "hop": "device-gateway",
        "client_id": DEVICE_ID,
        "client_nonce": b64e(cu.random_bytes(16)),
    }
    assert gateway_http.post("/handshake", json=hello).status_code == 200
    assert gateway_http.post("/handshake", json=hello).status_code == 409


def test_nonce_not_matching_the_counter_is_rejected(gw):
    """The nonce is derived, not chosen. A mismatch is protocol abuse."""
    gateway_http, _, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)
    seq, _, ct = session.seal(reading())

    assert_rejected(session.post(seq, b"\x00" * 12, ct), "replay")
    assert_rejected(session.post(seq, b"\x00" * 3, ct), "replay")  # wrong length


# ----------------------------------------------------------------- wrong key


def test_wrong_device_key_is_rejected(gw):
    """Hop 1 auth is implicit: an impostor fails at the first AEAD open."""
    gateway_http, cloud_http, keys_dir = gw
    impostor = cu.generate_private_key()

    session = Hop1Session(gateway_http, keys_dir, device_key=impostor)
    assert_rejected(session.send(reading()), "bad_tag")
    assert cloud_http.get("/readings").json()["count"] == 0


def test_wrong_gateway_key_is_rejected(gw):
    """A device pinned to the wrong gateway key derives a useless session."""
    gateway_http, cloud_http, keys_dir = gw
    wrong_gateway = cu.generate_private_key().public_key()

    session = Hop1Session(gateway_http, keys_dir, gateway_pub=wrong_gateway)
    assert_rejected(session.send(reading()), "bad_tag")
    assert cloud_http.get("/readings").json()["count"] == 0


def test_unknown_device_id_is_refused_at_handshake(gw):
    gateway_http, _, _ = gw
    response = gateway_http.post(
        "/handshake",
        json={
            "protocol": PROTOCOL,
            "hop": "device-gateway",
            "client_id": "device-not-registered",
            "client_nonce": b64e(cu.random_bytes(16)),
        },
    )
    assert response.status_code == 403


def test_forged_gateway_signature_is_refused_by_cloud(gw):
    """Hop 2 auth is explicit, so a forgery fails at the handshake itself."""
    _, cloud_http, _ = gw
    from services.common.handshake import KeyShare, hop2_v2_client_transcript
    from services.common.suites import SUITE_HYBRID

    impostor = cu.generate_private_key()
    x_pub = cu.x25519_public_bytes(cu.generate_x25519_private_key().public_key())
    ek = cu.mlkem768_encapsulation_key_bytes(cu.generate_mlkem768_private_key())
    nonce = cu.random_bytes(16)
    offered = [SUITE_HYBRID]
    shares = {SUITE_HYBRID: KeyShare(x25519_pub=x_pub, mlkem768_ek=ek)}

    response = cloud_http.post(
        "/handshake",
        json={
            "protocol": PROTOCOL_V2,
            "hop": "gateway-cloud",
            "client_id": "gw-01",
            "client_nonce": b64e(nonce),
            "offered_suites": offered,
            "key_shares": {SUITE_HYBRID: {"x25519_pub": b64e(x_pub), "mlkem768_ek": b64e(ek)}},
            "sig": b64e(
                cu.sign(impostor, hop2_v2_client_transcript("gw-01", nonce, offered, shares))
            ),
        },
    )
    assert response.status_code == 403


def test_signature_over_a_different_transcript_is_refused(gw):
    """Signing the right way over the wrong bytes must not verify."""
    _, cloud_http, keys_dir = gw
    from services.common.handshake import KeyShare, hop2_v2_client_transcript
    from services.common.suites import SUITE_HYBRID

    real_key = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")
    x_pub = cu.x25519_public_bytes(cu.generate_x25519_private_key().public_key())
    ek = cu.mlkem768_encapsulation_key_bytes(cu.generate_mlkem768_private_key())
    nonce = cu.random_bytes(16)
    offered = [SUITE_HYBRID]
    shares = {SUITE_HYBRID: KeyShare(x25519_pub=x_pub, mlkem768_ek=ek)}

    # Valid signature, but over a different nonce than the one we send.
    wrong = hop2_v2_client_transcript("gw-01", cu.random_bytes(16), offered, shares)
    response = cloud_http.post(
        "/handshake",
        json={
            "protocol": PROTOCOL_V2,
            "hop": "gateway-cloud",
            "client_id": "gw-01",
            "client_nonce": b64e(nonce),
            "offered_suites": offered,
            "key_shares": {SUITE_HYBRID: {"x25519_pub": b64e(x_pub), "mlkem768_ek": b64e(ek)}},
            "sig": b64e(cu.sign(real_key, wrong)),
        },
    )
    assert response.status_code == 403


def test_invalid_curve_point_is_rejected_not_crashed(keys_dir: Path):
    """An off-curve P-256 point must be refused before any ECDH happens.

    Built with a classical-permitting policy on purpose: under the default
    'require' the handshake would be refused earlier, for a different and much
    less interesting reason, and this check would never run.
    """
    from services.common.handshake import KeyShare, hop2_v2_client_transcript
    from services.common.suites import SUITE_CLASSICAL, Policy

    cloud_app = create_cloud_app(
        keys_dir=str(keys_dir), db_path=":memory:", policy=Policy.CLASSICAL_ONLY
    )
    cloud_http = TestClient(cloud_app, base_url="http://cloud")

    real_key = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")
    nonce = cu.random_bytes(16)
    bogus = b"\x04" + b"\x01" * 64  # well-formed encoding, not on P-256
    offered = [SUITE_CLASSICAL]
    shares = {SUITE_CLASSICAL: KeyShare(p256_pub=bogus)}

    response = cloud_http.post(
        "/handshake",
        json={
            "protocol": PROTOCOL_V2,
            "hop": "gateway-cloud",
            "client_id": "gw-01",
            "client_nonce": b64e(nonce),
            "offered_suites": offered,
            "key_shares": {SUITE_CLASSICAL: {"eph_pub": b64e(bogus)}},
            "sig": b64e(
                cu.sign(real_key, hop2_v2_client_transcript("gw-01", nonce, offered, shares))
            ),
        },
    )
    assert response.status_code == 400
    assert cloud_http.get("/health").json()["status"] == "ok"
    cloud_http.close()


# ------------------------------------------------------- malformed readings


@pytest.mark.parametrize(
    "mutation",
    [
        {"temp_max_c": 500.0},
        {"temp_min_c": -300.0},
        {"precip_mm": -1.0},
        {"wind_max_kmh": -5.0},
        {"temp_min_c": 40.0, "temp_max_c": 10.0},
        {"date": "2024-13-45"},
        {"date": "yesterday"},
        {"temp_max_c": "7.4"},
        {"temp_max_c": None},
        {"temp_max_c": True},
        {"temp_max_c": float("nan")},
        {"temp_max_c": float("inf")},
    ],
)
def test_malformed_reading_is_rejected_and_not_stored(gw, mutation):
    gateway_http, cloud_http, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    response = session.send({**reading(), **mutation})
    assert_rejected(response, "validation_failed")
    assert cloud_http.get("/readings").json()["count"] == 0

    # Service is still healthy and accepts a good reading next.
    assert session.send(reading("2024-02-02")).json()["status"] == "accepted"


@pytest.mark.parametrize("missing", ["date", "temp_max_c", "temp_min_c",
                                     "precip_mm", "wind_max_kmh"])
def test_missing_field_is_rejected(gw, missing):
    gateway_http, cloud_http, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    payload = reading()
    del payload[missing]
    assert_rejected(session.send(payload), "validation_failed")
    assert cloud_http.get("/readings").json()["count"] == 0


def test_payload_that_is_not_json_is_rejected(gw):
    gateway_http, cloud_http, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    seq, nonce, ct = session.sender.encrypt(b"\xff\xfe not json at all")
    response = session.post(seq, nonce, ct)
    assert 400 <= response.status_code < 500
    assert cloud_http.get("/readings").json()["count"] == 0


@pytest.mark.parametrize("payload", [b"[]", b'"a string"', b"42", b"null"])
def test_json_that_is_not_an_object_is_rejected(gw, payload):
    """validate_reading expects a mapping; a list or scalar must not crash it."""
    gateway_http, _, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    seq, nonce, ct = session.sender.encrypt(payload)
    response = session.post(seq, nonce, ct)
    assert 400 <= response.status_code < 500


def test_device_id_not_matching_the_session_is_rejected(gw):
    gateway_http, cloud_http, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    assert_rejected(
        session.send({**reading(), "device_id": "someone-else"}), "device_id_mismatch"
    )
    assert cloud_http.get("/readings").json()["count"] == 0


# ------------------------------------------------------ malformed wire frames


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"session_id": "!!!not base64!!!", "seq": 0, "nonce": "AAAA", "ct": "AAAA"},
        {"session_id": b64e(b"x" * 16), "seq": -1, "nonce": b64e(b"n" * 12), "ct": b64e(b"c")},
        {"session_id": b64e(b"x" * 16), "seq": "zero", "nonce": b64e(b"n" * 12), "ct": b64e(b"c")},
        {"session_id": b64e(b"x" * 16), "seq": True, "nonce": b64e(b"n" * 12), "ct": b64e(b"c")},
        {"session_id": b64e(b"x" * 16), "seq": 2**70, "nonce": b64e(b"n" * 12), "ct": b64e(b"c")},
        {"session_id": None, "seq": 0, "nonce": None, "ct": None},
    ],
)
def test_malformed_ingest_frame_is_rejected(gw, body):
    gateway_http, _, _ = gw
    response = gateway_http.post("/ingest", json=body)
    assert 400 <= response.status_code < 500, response.text[:200]
    # And the service still works.
    assert gateway_http.get("/health").json()["status"] == "ok"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"protocol": "wrong/9", "hop": "device-gateway",
         "client_id": DEVICE_ID, "client_nonce": b64e(b"n" * 16)},
        {"protocol": PROTOCOL, "hop": "gateway-cloud",
         "client_id": DEVICE_ID, "client_nonce": b64e(b"n" * 16)},
        {"protocol": PROTOCOL, "hop": "device-gateway",
         "client_id": DEVICE_ID, "client_nonce": "not-base64!"},
        {"protocol": PROTOCOL, "hop": "device-gateway",
         "client_id": DEVICE_ID, "client_nonce": b64e(b"short")},
        {"protocol": PROTOCOL, "hop": "device-gateway",
         "client_id": 12345, "client_nonce": b64e(b"n" * 16)},
    ],
)
def test_malformed_handshake_is_rejected(gw, body):
    gateway_http, _, _ = gw
    response = gateway_http.post("/handshake", json=body)
    assert 400 <= response.status_code < 500, response.text[:200]
    assert gateway_http.get("/health").json()["status"] == "ok"


def test_unknown_session_id_is_rejected(gw):
    gateway_http, _, _ = gw
    response = gateway_http.post(
        "/ingest",
        json={
            "session_id": b64e(cu.random_bytes(16)),
            "seq": 0,
            "nonce": b64e(cu.random_bytes(12)),
            "ct": b64e(cu.random_bytes(32)),
        },
    )
    assert_rejected(response, "session_expired")


def test_oversized_ciphertext_is_rejected_not_crashed(gw):
    """A 1 MB blob must be refused cleanly rather than exhausting anything."""
    gateway_http, _, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    response = session.post(0, session.prefix + b"\x00" * 8, cu.random_bytes(1_000_000))
    assert 400 <= response.status_code < 500
    assert gateway_http.get("/health").json()["status"] == "ok"


# --------------------------------------------------- parser-level robustness


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\n\n\n",
        "only,one,block\n1,2,3\n",
        "lat,lon\n1,2\n\ntime,temperature_2m_max\n2024-01-01,7.4\n",
        "lat,lon\n\n\ntime,temperature_2m_max (°C),temperature_2m_min (°C),"
        "precipitation_sum (mm),windspeed_10m_max (km/h)\n2024-01-01,7.4,3.4,1.8,19.7\n",
    ],
)
def test_malformed_source_file_raises_a_clean_error(text):
    """The parser must raise WeatherDataError, never IndexError or KeyError."""
    with pytest.raises(WeatherDataError):
        parse_weather_text(text)


def test_validate_reading_rejects_non_mapping_input():
    for bad in ([], "string", 42, None):
        with pytest.raises((ValidationError, TypeError)):
            validate_reading(bad)  # type: ignore[arg-type]


# --------------------------------------------------- never crash, never leak


def test_rejection_reasons_do_not_echo_payload_values(gw):
    """Reasons name the field, never the value -- plaintext must not leak."""
    gateway_http, _, keys_dir = gw
    session = Hop1Session(gateway_http, keys_dir)

    secret = 999.123456
    response = session.send({**reading(), "temp_max_c": secret})

    assert_rejected(response, "validation_failed")
    assert "999.123456" not in response.text


def test_aead_wrapper_raises_rather_than_returning_garbage():
    """The wrapper must never hand back unauthenticated plaintext."""
    key = cu.random_bytes(32)
    sid, prefix = cu.random_bytes(16), cu.random_bytes(4)
    sender = cu.AeadSender(key, sid, prefix)
    receiver = cu.AeadReceiver(cu.random_bytes(32), sid, prefix)

    seq, nonce, ct = sender.encrypt(b"sensitive reading")
    with pytest.raises(InvalidTag):
        receiver.decrypt(seq, nonce, ct)


def test_bad_key_length_is_refused_at_construction():
    for bad_length in (0, 16, 31, 33):
        with pytest.raises(ValueError, match="32 bytes"):
            cu.AeadSender(cu.random_bytes(bad_length), b"s" * 16, b"p" * 4)
        with pytest.raises(ValueError, match="32 bytes"):
            cu.AeadReceiver(cu.random_bytes(bad_length), b"s" * 16, b"p" * 4)


def test_bad_nonce_prefix_length_is_refused():
    sender = cu.AeadSender(cu.random_bytes(32), b"s" * 16, b"bad")
    with pytest.raises(ValueError, match="nonce prefix"):
        sender.encrypt(b"x")


# ------------------------------------------ hop 2 directly against the cloud


def test_hop2_happy_path_stores(gw, keys_dir: Path):
    """Baseline for the hop 2 negative cases below."""
    _, cloud_http, keys_dir = gw
    session = Hop2Session(cloud_http, keys_dir)

    assert session.send(envelope()).json()["status"] == "accepted"
    assert cloud_http.get("/readings").json()["count"] == 1


def test_hop2_tampered_ciphertext_is_rejected(gw):
    _, cloud_http, keys_dir = gw
    session = Hop2Session(cloud_http, keys_dir)

    seq, nonce, ct = session.seal(envelope())
    assert_rejected(session.post(seq, nonce, bytes([ct[0] ^ 0x01]) + ct[1:]), "bad_tag")
    assert cloud_http.get("/readings").json()["count"] == 0

    # Intact message still accepted -- the cloud survived.
    assert session.post(seq, nonce, ct).json()["status"] == "accepted"


def test_hop2_replay_is_rejected(gw):
    _, cloud_http, keys_dir = gw
    session = Hop2Session(cloud_http, keys_dir)

    seq, nonce, ct = session.seal(envelope())
    assert session.post(seq, nonce, ct).json()["status"] == "accepted"
    assert_rejected(session.post(seq, nonce, ct), "replay")
    assert cloud_http.get("/readings").json()["count"] == 1


def test_hop2_malformed_reading_is_rejected(gw):
    _, cloud_http, keys_dir = gw
    session = Hop2Session(cloud_http, keys_dir)

    bad = envelope()
    bad["reading"]["temp_max_c"] = 500.0
    assert_rejected(session.send(bad), "validation_failed")
    assert cloud_http.get("/readings").json()["count"] == 0


@pytest.mark.parametrize(
    "broken",
    [
        {"reading": None},
        {"reading": "not an object"},
        {"device_id": 12345},
        {"gateway_id": None},
        {"received_at": []},
    ],
)
def test_hop2_malformed_envelope_is_rejected(gw, broken):
    _, cloud_http, keys_dir = gw
    session = Hop2Session(cloud_http, keys_dir)

    response = session.send(envelope(**broken))
    assert 400 <= response.status_code < 500, response.text[:200]
    assert cloud_http.get("/readings").json()["count"] == 0
    assert cloud_http.get("/health").json()["status"] == "ok"


def test_hop2_envelope_missing_reading_is_rejected(gw):
    _, cloud_http, keys_dir = gw
    session = Hop2Session(cloud_http, keys_dir)

    incomplete = envelope()
    del incomplete["reading"]
    response = session.send(incomplete)
    assert 400 <= response.status_code < 500
    assert cloud_http.get("/readings").json()["count"] == 0


def test_hop2_non_json_payload_is_rejected(gw):
    _, cloud_http, keys_dir = gw
    session = Hop2Session(cloud_http, keys_dir)

    seq, nonce, ct = session.sender.encrypt(b"\x00\x01 definitely not json")
    response = session.post(seq, nonce, ct)
    assert 400 <= response.status_code < 500
    assert cloud_http.get("/health").json()["status"] == "ok"


def test_hop2_unknown_session_is_rejected(gw):
    _, cloud_http, _ = gw
    response = cloud_http.post(
        "/ingest",
        json={
            "session_id": b64e(cu.random_bytes(16)),
            "seq": 0,
            "nonce": b64e(cu.random_bytes(12)),
            "ct": b64e(cu.random_bytes(48)),
        },
    )
    assert_rejected(response, "session_expired")


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"session_id": None, "seq": 0, "nonce": None, "ct": None},
        {"session_id": "!!!", "seq": 0, "nonce": "AAAA", "ct": "AAAA"},
        {"session_id": b64e(b"x" * 16), "seq": -5,
         "nonce": b64e(b"n" * 12), "ct": b64e(b"c")},
    ],
)
def test_hop2_malformed_frame_is_rejected(gw, body):
    _, cloud_http, _ = gw
    response = cloud_http.post("/ingest", json=body)
    assert 400 <= response.status_code < 500, response.text[:200]
    assert cloud_http.get("/health").json()["status"] == "ok"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"protocol": "wrong/9", "hop": "gateway-cloud", "client_id": "gw-01"},
        {"protocol": PROTOCOL_V2, "hop": "device-gateway", "client_id": "gw-01"},
        {"protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": "unknown-gw"},
        {"protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": "gw-01",
         "client_nonce": "not-base64!", "offered_suites": ["hybrid-x25519-mlkem768"],
         "key_shares": {}, "sig": "AAAA"},
        {"protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": "gw-01",
         "client_nonce": b64e(b"too-short"), "offered_suites": ["hybrid-x25519-mlkem768"],
         "key_shares": {}, "sig": "AAAA"},
        {"protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": "gw-01",
         "client_nonce": b64e(b"n" * 16), "offered_suites": "not-a-list",
         "key_shares": {}, "sig": "AAAA"},
        {"protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": "gw-01",
         "client_nonce": b64e(b"n" * 16), "offered_suites": [], "key_shares": {},
         "sig": "AAAA"},
        {"protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": "gw-01",
         "client_nonce": b64e(b"n" * 16), "offered_suites": ["a"] * 99,
         "key_shares": {}, "sig": "AAAA"},
        {"protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": "gw-01",
         "client_nonce": b64e(b"n" * 16), "offered_suites": [123],
         "key_shares": {}, "sig": "AAAA"},
        {"protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": "gw-01",
         "client_nonce": b64e(b"n" * 16), "offered_suites": ["hybrid-x25519-mlkem768"],
         "key_shares": "not-an-object", "sig": "AAAA"},
    ],
)
def test_hop2_malformed_handshake_is_rejected(gw, body):
    _, cloud_http, _ = gw
    response = cloud_http.post("/handshake", json=body)
    assert 400 <= response.status_code < 500, response.text[:200]
    assert cloud_http.get("/health").json()["status"] == "ok"


def test_hop2_replayed_client_hello_is_rejected(gw, keys_dir: Path):
    from services.common.handshake import KeyShare, hop2_v2_client_transcript
    from services.common.suites import SUITE_HYBRID

    _, cloud_http, keys_dir = gw
    key = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")
    nonce = cu.random_bytes(16)
    x_pub = cu.x25519_public_bytes(cu.generate_x25519_private_key().public_key())
    ek = cu.mlkem768_encapsulation_key_bytes(cu.generate_mlkem768_private_key())
    offered = [SUITE_HYBRID]
    shares = {SUITE_HYBRID: KeyShare(x25519_pub=x_pub, mlkem768_ek=ek)}

    hello = {
        "protocol": PROTOCOL_V2,
        "hop": "gateway-cloud",
        "client_id": "gw-01",
        "client_nonce": b64e(nonce),
        "offered_suites": offered,
        "key_shares": {SUITE_HYBRID: {"x25519_pub": b64e(x_pub), "mlkem768_ek": b64e(ek)}},
        "sig": b64e(cu.sign(key, hop2_v2_client_transcript("gw-01", nonce, offered, shares))),
    }

    assert cloud_http.post("/handshake", json=hello).status_code == 200
    assert cloud_http.post("/handshake", json=hello).status_code == 409


def test_read_api_handles_absent_and_odd_queries(gw):
    """The read API must 404 and validate, not 500."""
    _, cloud_http, _ = gw

    assert cloud_http.get("/readings/1999-01-01").status_code == 404
    assert cloud_http.get("/readings?limit=0").status_code == 422      # below ge=1
    assert cloud_http.get("/readings?limit=100000").status_code == 422  # above le=1000
    assert cloud_http.get("/readings?limit=notanumber").status_code == 422
    assert cloud_http.get("/readings?since=garbage").status_code == 200  # no rows
    assert cloud_http.get("/readings?device_id=nobody").json()["count"] == 0


def test_loading_a_non_p256_key_is_refused(tmp_path: Path):
    """Key loaders must reject the wrong curve rather than silently accepting."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP384R1())
    path = tmp_path / "p384_priv.pem"
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="P-256"):
        cu.load_private_key(path)
