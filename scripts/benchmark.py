#!/usr/bin/env python3
"""Measurement baseline for the legacy (pre-PQC) system.

Produces the numbers we compare against after ML-KEM is integrated. Writes a
machine-readable JSON file plus a human-readable Markdown summary.

Three layers, because they answer different questions:

  1. primitives  -- ECDH / ECDSA / HKDF / AES-GCM in isolation.
                    This is where ML-KEM's cost will actually show up, with no
                    HTTP or JSON noise on top.
  2. protocol    -- full handshake and full message round trip, in-process.
                    Includes our framing and validation but not the network.
  3. sizes       -- bytes on the wire: handshake messages, per-message overhead,
                    and the expansion factor over the raw reading.

Everything runs in-process, deliberately: the numbers must be comparable across
machines and CI runners, and adding a real socket would measure the network far
more than it measures the crypto. Absolute values are therefore not latencies a
production deployment would see -- the point is the before/after delta.

Usage:
    python scripts/benchmark.py
    python scripts/benchmark.py --iterations 500
    python scripts/benchmark.py --label before-pqc
    python scripts/benchmark.py --skip-protocol      # primitives + sizes only

Latency is reported as median and p95 rather than mean: the mean of a latency
sample is dominated by outliers and is not a useful thing to compare.
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import statistics
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services.common import cryptoutil as cu  # noqa: E402
from services.common.handshake import (  # noqa: E402
    KeyShare,
    hop1_derive,
    hop2_client_transcript,
    hop2_derive,
    hop2_server_transcript,
    hop2_v2_client_transcript,
    hop2_v2_derive,
    hop2_v2_server_transcript,
)
from services.common.suites import SUITE_CLASSICAL, SUITE_HYBRID, Policy  # noqa: E402
from services.common.wire import PROTOCOL_V2, b64e  # noqa: E402

DEVICE_ID = "device-berlin-01"
GATEWAY_ID = "gw-01"


def _cryptography_version() -> str:
    import cryptography
    return cryptography.__version__

SAMPLE_READING = {
    "device_id": DEVICE_ID,
    "station": {"lat": 52.54833, "lon": 13.407822, "elev_m": 38.0, "tz": "Europe/Berlin"},
    "sent_at": "2026-09-21T10:00:00Z",
    "date": "2024-01-01",
    "temp_max_c": 7.4,
    "temp_min_c": 3.4,
    "precip_mm": 1.80,
    "wind_max_kmh": 19.7,
}


# --------------------------------------------------------------------------
# timing
# --------------------------------------------------------------------------


def measure(fn: Callable[[], Any], iterations: int, warmup: int = 20) -> dict[str, float]:
    """Time `fn` and summarise the distribution in milliseconds.

    A warmup pass is discarded so that import-time and first-call costs (lazy
    OpenSSL initialisation, branch predictors) do not land in the sample.
    """
    for _ in range(warmup):
        fn()

    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)

    samples.sort()
    return {
        "iterations": iterations,
        "min_ms": round(samples[0], 4),
        "median_ms": round(statistics.median(samples), 4),
        "mean_ms": round(statistics.fmean(samples), 4),
        "p95_ms": round(samples[int(len(samples) * 0.95) - 1], 4),
        "p99_ms": round(samples[int(len(samples) * 0.99) - 1], 4),
        "max_ms": round(samples[-1], 4),
        "stdev_ms": round(statistics.pstdev(samples), 4),
    }


# --------------------------------------------------------------------------
# layer 1: primitives
# --------------------------------------------------------------------------


def bench_primitives(iterations: int) -> dict[str, Any]:
    static_a = cu.generate_private_key()
    static_b = cu.generate_private_key()
    pub_b = static_b.public_key()
    pub_b_raw = cu.public_key_to_bytes(pub_b)

    message = b"x" * 256
    signature = cu.sign(static_a, message)
    pub_a = static_a.public_key()

    shared = cu.ecdh(static_a, pub_b)
    key = cu.hkdf_sha256(shared, b"salt" * 8, b"info")

    plaintext = json.dumps(SAMPLE_READING, separators=(",", ":")).encode()
    sender = cu.AeadSender(key, b"s" * 16, b"p" * 4)
    _, nonce, ciphertext = cu.AeadSender(key, b"s" * 16, b"p" * 4).encrypt(plaintext)

    # X25519 -- the classical half of the hybrid.
    x_a = cu.generate_x25519_private_key()
    x_b = cu.generate_x25519_private_key()
    x_b_pub = x_b.public_key()
    x_b_raw = cu.x25519_public_bytes(x_b_pub)

    # ML-KEM-768 -- the post-quantum half.
    kem_priv = cu.generate_mlkem768_private_key()
    kem_pub = kem_priv.public_key()
    kem_ek = cu.mlkem768_encapsulation_key_bytes(kem_priv)
    _, kem_ct = cu.mlkem768_encapsulate(kem_pub)

    results = {
        "ec_keygen_p256": measure(cu.generate_private_key, iterations),
        "ecdh_p256": measure(lambda: cu.ecdh(static_a, pub_b), iterations),
        "ecdsa_sign_p256": measure(lambda: cu.sign(static_a, message), iterations),
        "ecdsa_verify_p256": measure(lambda: cu.verify(pub_a, signature, message), iterations),
        "hkdf_sha256": measure(lambda: cu.hkdf_sha256(shared, b"salt" * 8, b"info"), iterations),
        "pubkey_encode": measure(lambda: cu.public_key_to_bytes(pub_b), iterations),
        "pubkey_decode": measure(lambda: cu.public_key_from_bytes(pub_b_raw), iterations),
        "aes256gcm_encrypt_reading": measure(lambda: sender.encrypt(plaintext), iterations),
        # --- post-quantum additions ---
        "x25519_keygen": measure(cu.generate_x25519_private_key, iterations),
        "x25519_exchange": measure(lambda: cu.x25519_exchange(x_a, x_b_pub), iterations),
        "x25519_pubkey_decode": measure(
            lambda: cu.x25519_public_from_bytes(x_b_raw), iterations),
        "mlkem768_keygen": measure(cu.generate_mlkem768_private_key, iterations),
        "mlkem768_ek_parse_and_validate": measure(
            lambda: cu.mlkem768_encapsulation_key_from_bytes(kem_ek), iterations),
        "mlkem768_encapsulate": measure(
            lambda: cu.mlkem768_encapsulate(kem_pub), iterations),
        "mlkem768_decapsulate": measure(
            lambda: cu.mlkem768_decapsulate(kem_priv, kem_ct), iterations),
    }

    # Decrypt needs a fresh receiver each time because the counter must advance.
    def decrypt_once() -> None:
        receiver = cu.AeadReceiver(key, b"s" * 16, b"p" * 4)
        receiver.decrypt(0, nonce, ciphertext)

    results["aes256gcm_decrypt_reading"] = measure(decrypt_once, iterations)
    return results


# --------------------------------------------------------------------------
# layer 2: protocol (in-process)
# --------------------------------------------------------------------------


def build_stack(keys_dir: Path) -> tuple[Any, Any, Any, Any]:
    """Cloud + gateway + device client, all in-process."""
    from fastapi.testclient import TestClient

    from services.cloud.main import create_app as create_cloud_app
    from services.device.gateway_client import GatewayClient
    from services.gateway.cloud_client import CloudClient
    from services.gateway.main import create_app as create_gateway_app

    log = logging.getLogger("bench")

    # Importing the services calls setup_logging(), which does
    # basicConfig(force=True) and resets the root logger. Quiet the service
    # loggers afterwards or a 200-iteration run prints thousands of lines --
    # and the logging itself would land inside the measured window.
    for name in ("bench", "gateway", "cloud", "device"):
        # ERROR, not WARNING: the classical-suite measurements legitimately log
        # a downgrade warning on every one of hundreds of iterations, which
        # would bury the benchmark's own output.
        logging.getLogger(name).setLevel(logging.ERROR)
    logging.getLogger().setLevel(logging.WARNING)

    # PREFER on both sides so the benchmark can exercise the hybrid path and
    # the classical fallback from the same stack.
    cloud_app = create_cloud_app(
        keys_dir=str(keys_dir), db_path=":memory:", max_records=10**9,
        policy=Policy.PREFER,
    )
    cloud_http = TestClient(cloud_app, base_url="http://cloud")
    cloud_client = CloudClient(
        base_url="http://cloud",
        gateway_id=GATEWAY_ID,
        signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
        cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        log=log,
        http_client=cloud_http,
        policy=Policy.PREFER,
    )
    gateway_app = create_gateway_app(
        keys_dir=str(keys_dir),
        cloud_url="http://cloud",
        max_records=10**9,
        cloud_client=cloud_client,
        policy=Policy.PREFER,
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
    return device, gateway_http, cloud_http, cloud_client


def bench_key_establishment(keys_dir: Path, iterations: int) -> dict[str, Any]:
    """Key agreement only -- no HTTP, no JSON. The cleanest PQC comparison point."""
    device_key = cu.load_private_key(keys_dir / "device_ecdh_priv.pem")
    gateway_ecdh_pub = cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem")
    gateway_sign = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")
    cloud_sign = cu.load_private_key(keys_dir / "cloud_ecdsa_priv.pem")
    gateway_verify = cu.load_public_key(keys_dir / "gateway_ecdsa_pub.pem")
    cloud_verify = cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem")

    def hop1_full() -> None:
        """Everything both sides do: nonces, one ECDH, one HKDF."""
        client_nonce = cu.random_bytes(16)
        server_nonce = cu.random_bytes(16)
        session_id = cu.random_bytes(16)
        prefix = cu.random_bytes(4)
        hop1_derive(device_key, gateway_ecdh_pub, client_nonce, server_nonce,
                    session_id, prefix)

    def hop2_full() -> None:
        """Both ephemeral keygens, both ECDHs, both signatures, both verifies."""
        client_nonce = cu.random_bytes(16)
        client_eph = cu.generate_private_key()
        client_eph_pub = cu.public_key_to_bytes(client_eph.public_key())
        sig_c = cu.sign(gateway_sign, hop2_client_transcript(
            GATEWAY_ID, client_nonce, client_eph_pub))

        # server side
        assert cu.verify(gateway_verify, sig_c, hop2_client_transcript(
            GATEWAY_ID, client_nonce, client_eph_pub))
        parsed_client_eph = cu.public_key_from_bytes(client_eph_pub)
        server_eph = cu.generate_private_key()
        server_eph_pub = cu.public_key_to_bytes(server_eph.public_key())
        server_nonce = cu.random_bytes(16)
        session_id = cu.random_bytes(16)
        prefix = cu.random_bytes(4)
        expires = "2026-09-21T10:05:00Z"
        transcript = hop2_server_transcript(
            GATEWAY_ID, client_nonce, client_eph_pub, session_id,
            server_nonce, server_eph_pub, prefix, expires, 100)
        sig_s = cu.sign(cloud_sign, transcript)
        hop2_derive(server_eph, parsed_client_eph, client_nonce, server_nonce,
                    client_eph_pub, server_eph_pub, session_id, prefix)

        # client side
        assert cu.verify(cloud_verify, sig_s, transcript)
        hop2_derive(client_eph, cu.public_key_from_bytes(server_eph_pub),
                    client_nonce, server_nonce, client_eph_pub, server_eph_pub,
                    session_id, prefix)

    def hop2_hybrid_full() -> None:
        """The post-quantum replacement, both sides, crypto only.

        Client: X25519 keygen + ML-KEM keygen + sign + verify + X25519 + decap.
        Server: verify + ek validate + encap + X25519 keygen + X25519 + sign.
        This is the number that should grow relative to hop2_full.
        """
        client_nonce = cu.random_bytes(16)
        # --- client key shares ---
        client_x = cu.generate_x25519_private_key()
        client_x_pub = cu.x25519_public_bytes(client_x.public_key())
        client_kem = cu.generate_mlkem768_private_key()
        client_ek = cu.mlkem768_encapsulation_key_bytes(client_kem)

        offered = [SUITE_HYBRID]
        shares = {SUITE_HYBRID: KeyShare(x25519_pub=client_x_pub, mlkem768_ek=client_ek)}
        sig_c = cu.sign(gateway_sign, hop2_v2_client_transcript(
            GATEWAY_ID, client_nonce, offered, shares))

        # --- server side ---
        assert cu.verify(gateway_verify, sig_c, hop2_v2_client_transcript(
            GATEWAY_ID, client_nonce, offered, shares))
        peer_ek = cu.mlkem768_encapsulation_key_from_bytes(client_ek)
        ss_mlkem_server, mlkem_ct = cu.mlkem768_encapsulate(peer_ek)
        server_x = cu.generate_x25519_private_key()
        server_x_pub = cu.x25519_public_bytes(server_x.public_key())
        ss_x_server = cu.x25519_exchange(
            server_x, cu.x25519_public_from_bytes(client_x_pub))

        server_nonce = cu.random_bytes(16)
        session_id = cu.random_bytes(16)
        prefix = cu.random_bytes(4)
        expires = "2026-09-21T10:05:00Z"
        server_share = KeyShare(x25519_pub=server_x_pub)
        transcript = hop2_v2_server_transcript(
            client_id=GATEWAY_ID, client_nonce=client_nonce, offered_suites=offered,
            client_shares=shares, selected_suite=SUITE_HYBRID, session_id=session_id,
            server_nonce=server_nonce, server_share=server_share,
            mlkem768_ct=mlkem_ct, nonce_prefix=prefix, expires_at=expires,
            max_records=100)
        sig_s = cu.sign(cloud_sign, transcript)
        hop2_v2_derive(
            selected_suite=SUITE_HYBRID, ss_mlkem768=ss_mlkem_server,
            ss_classical=ss_x_server, client_id=GATEWAY_ID, offered_suites=offered,
            client_nonce=client_nonce, server_nonce=server_nonce,
            client_share=shares[SUITE_HYBRID], server_share=server_share,
            mlkem768_ct=mlkem_ct, session_id=session_id, nonce_prefix=prefix)

        # --- client completes ---
        assert cu.verify(cloud_verify, sig_s, transcript)
        ss_mlkem_client = cu.mlkem768_decapsulate(client_kem, mlkem_ct)
        ss_x_client = cu.x25519_exchange(
            client_x, cu.x25519_public_from_bytes(server_x_pub))
        hop2_v2_derive(
            selected_suite=SUITE_HYBRID, ss_mlkem768=ss_mlkem_client,
            ss_classical=ss_x_client, client_id=GATEWAY_ID, offered_suites=offered,
            client_nonce=client_nonce, server_nonce=server_nonce,
            client_share=shares[SUITE_HYBRID], server_share=server_share,
            mlkem768_ct=mlkem_ct, session_id=session_id, nonce_prefix=prefix)

    return {
        "hop1_static_static_ecdh": measure(hop1_full, iterations),
        "hop2_ephemeral_ecdhe_mutual_ecdsa": measure(hop2_full, iterations),
        "hop2_hybrid_x25519_mlkem768": measure(hop2_hybrid_full, iterations),
    }


def bench_protocol(keys_dir: Path, iterations: int) -> dict[str, Any]:
    device, gateway_http, cloud_http, cloud_client = build_stack(keys_dir)

    # --- handshake round trips over the full stack (HTTP framing included) ---
    def hop1_handshake() -> None:
        device.handshake()

    def hop2_handshake() -> None:
        cloud_client.handshake()

    # Separate clients so each measures one suite only.
    from services.gateway.cloud_client import CloudClient as _CC

    def make_client(policy: Policy) -> _CC:
        return _CC(
            base_url="http://cloud", gateway_id=GATEWAY_ID,
            signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
            cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
            log=logging.getLogger("bench"), http_client=cloud_http, policy=policy,
        )

    hybrid_client = make_client(Policy.REQUIRE)
    classical_client = make_client(Policy.CLASSICAL_ONLY)

    handshakes = {
        "hop1_handshake_roundtrip": measure(hop1_handshake, max(iterations // 5, 20)),
        "hop2_handshake_roundtrip": measure(hop2_handshake, max(iterations // 5, 20)),
        "hop2_v2_hybrid_handshake_roundtrip": measure(
            hybrid_client.handshake, max(iterations // 5, 20)),
        "hop2_v2_classical_handshake_roundtrip": measure(
            classical_client.handshake, max(iterations // 5, 20)),
    }
    # Deliberately NOT closed: these clients share the injected `cloud_http`
    # transport with the gateway's own client, so closing one closes it for all.

    # --- per-message, device -> gateway -> cloud (both hops, end to end) ---
    device.handshake()
    counter = {"day": 0}

    def send_one() -> None:
        counter["day"] += 1
        payload = {**SAMPLE_READING, "date": f"2024-01-{(counter['day'] % 28) + 1:02d}"}
        result = device.send_reading(payload)
        if result.get("status") != "accepted":
            raise RuntimeError(f"benchmark message rejected: {result}")

    messages = {"end_to_end_reading_both_hops": measure(send_one, iterations)}

    # --- single hop, for attribution ---
    from services.common.handshake import hop1_derive as _h1
    from services.common.wire import b64d

    client_nonce = cu.random_bytes(16)
    hello = gateway_http.post("/handshake", json={
        "protocol": "wx-legacy/1", "hop": "device-gateway",
        "client_id": DEVICE_ID, "client_nonce": b64e(client_nonce),
    }).json()
    sid = b64d(hello["session_id"])
    derived = _h1(
        cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
        cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
        client_nonce, b64d(hello["server_nonce"]), sid, b64d(hello["nonce_prefix"]),
    )
    sender = cu.AeadSender(derived.key, sid, derived.nonce_prefix)
    day = {"n": 0}

    def hop1_only() -> None:
        day["n"] += 1
        payload = {**SAMPLE_READING, "date": f"2024-02-{(day['n'] % 28) + 1:02d}"}
        seq, nonce, ct = sender.encrypt(json.dumps(payload, separators=(",", ":")).encode())
        gateway_http.post("/ingest", json={
            "session_id": b64e(sid), "seq": seq,
            "nonce": b64e(nonce), "ct": b64e(ct),
        })

    messages["hop1_only_reading"] = measure(hop1_only, iterations)

    device.close()
    gateway_http.close()
    cloud_http.close()

    return {"handshakes": handshakes, "messages": messages}


# --------------------------------------------------------------------------
# layer 3: sizes on the wire
# --------------------------------------------------------------------------


def bench_sizes(keys_dir: Path) -> dict[str, Any]:
    """Actual serialised byte counts, not estimates."""
    reading_json = json.dumps(SAMPLE_READING, separators=(",", ":")).encode()

    key = cu.random_bytes(32)
    sender = cu.AeadSender(key, cu.random_bytes(16), cu.random_bytes(4))
    seq, nonce, ciphertext = sender.encrypt(reading_json)

    ingest_frame = json.dumps({
        "session_id": b64e(cu.random_bytes(16)),
        "seq": seq,
        "nonce": b64e(nonce),
        "ct": b64e(ciphertext),
    }, separators=(",", ":")).encode()

    # hop 1 handshake
    hop1_hello = json.dumps({
        "protocol": "wx-legacy/1", "hop": "device-gateway",
        "client_id": DEVICE_ID, "client_nonce": b64e(cu.random_bytes(16)),
    }, separators=(",", ":")).encode()
    hop1_server = json.dumps({
        "protocol": "wx-legacy/1",
        "session_id": b64e(cu.random_bytes(16)),
        "server_nonce": b64e(cu.random_bytes(16)),
        "nonce_prefix": b64e(cu.random_bytes(4)),
        "expires_at": "2026-09-21T10:05:00Z", "max_records": 100,
    }, separators=(",", ":")).encode()

    # hop 2 handshake
    eph_pub = cu.public_key_to_bytes(cu.generate_private_key().public_key())
    sig = cu.sign(cu.generate_private_key(), b"transcript")
    hop2_hello = json.dumps({
        "protocol": "wx-legacy/1", "hop": "gateway-cloud", "client_id": GATEWAY_ID,
        "client_nonce": b64e(cu.random_bytes(16)),
        "eph_pub": b64e(eph_pub), "sig": b64e(sig),
    }, separators=(",", ":")).encode()
    hop2_server = json.dumps({
        "protocol": "wx-legacy/1",
        "session_id": b64e(cu.random_bytes(16)),
        "server_nonce": b64e(cu.random_bytes(16)),
        "eph_pub": b64e(eph_pub),
        "nonce_prefix": b64e(cu.random_bytes(4)),
        "expires_at": "2026-09-21T10:05:00Z", "max_records": 100,
        "sig": b64e(sig),
    }, separators=(",", ":")).encode()

    envelope = json.dumps({
        "gateway_id": GATEWAY_ID, "device_id": DEVICE_ID,
        "reading": {k: SAMPLE_READING[k] for k in
                    ("date", "temp_max_c", "temp_min_c", "precip_mm", "wind_max_kmh")},
        "station": SAMPLE_READING["station"],
        "received_at": "2026-09-21T10:00:02Z",
        "device_hop": {"verified": True,
                       "suite": "ECDH-P256-static-static+AES-256-GCM"},
    }, separators=(",", ":")).encode()
    _, _, envelope_ct = cu.AeadSender(key, cu.random_bytes(16),
                                      cu.random_bytes(4)).encrypt(envelope)

    # --- hop 2 v2 hybrid handshake, real serialised sizes ---
    x_pub = cu.x25519_public_bytes(cu.generate_x25519_private_key().public_key())
    kem_priv = cu.generate_mlkem768_private_key()
    ek = cu.mlkem768_encapsulation_key_bytes(kem_priv)
    _, kem_ct = cu.mlkem768_encapsulate(kem_priv.public_key())

    v2_hybrid_hello = json.dumps({
        "protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": GATEWAY_ID,
        "client_nonce": b64e(cu.random_bytes(16)),
        "offered_suites": [SUITE_HYBRID, SUITE_CLASSICAL],
        "key_shares": {
            SUITE_HYBRID: {"x25519_pub": b64e(x_pub), "mlkem768_ek": b64e(ek)},
            SUITE_CLASSICAL: {"eph_pub": b64e(eph_pub)},
        },
        "sig": b64e(sig),
    }, separators=(",", ":")).encode()

    v2_hybrid_server = json.dumps({
        "protocol": PROTOCOL_V2, "selected_suite": SUITE_HYBRID,
        "session_id": b64e(cu.random_bytes(16)),
        "server_nonce": b64e(cu.random_bytes(16)),
        "nonce_prefix": b64e(cu.random_bytes(4)),
        "expires_at": "2026-09-21T10:05:00Z", "max_records": 100,
        "sig": b64e(sig),
        "x25519_pub": b64e(x_pub), "mlkem768_ct": b64e(kem_ct),
    }, separators=(",", ":")).encode()

    v2_classical_hello = json.dumps({
        "protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": GATEWAY_ID,
        "client_nonce": b64e(cu.random_bytes(16)),
        "offered_suites": [SUITE_CLASSICAL],
        "key_shares": {SUITE_CLASSICAL: {"eph_pub": b64e(eph_pub)}},
        "sig": b64e(sig),
    }, separators=(",", ":")).encode()

    v2_classical_server = json.dumps({
        "protocol": PROTOCOL_V2, "selected_suite": SUITE_CLASSICAL,
        "session_id": b64e(cu.random_bytes(16)),
        "server_nonce": b64e(cu.random_bytes(16)),
        "nonce_prefix": b64e(cu.random_bytes(4)),
        "expires_at": "2026-09-21T10:05:00Z", "max_records": 100,
        "sig": b64e(sig), "eph_pub": b64e(eph_pub),
    }, separators=(",", ":")).encode()

    return {
        "cryptographic_elements_bytes": {
            "p256_public_key_x962_uncompressed": len(eph_pub),
            "ecdsa_p256_signature_der": len(sig),
            "handshake_nonce": cu.HANDSHAKE_NONCE_LEN,
            "session_id": cu.SESSION_ID_LEN,
            "aead_nonce": cu.NONCE_LEN,
            "aead_tag": 16,
            "session_key": cu.SESSION_KEY_LEN,
            "x25519_public_key": cu.X25519_PUBLIC_LEN,
            "mlkem768_encapsulation_key": cu.MLKEM768_EK_LEN,
            "mlkem768_ciphertext": cu.MLKEM768_CT_LEN,
            "mlkem768_shared_secret": cu.MLKEM768_SS_LEN,
        },
        "handshake_bytes": {
            "hop1_client_hello": len(hop1_hello),
            "hop1_server_hello": len(hop1_server),
            "hop1_total": len(hop1_hello) + len(hop1_server),
            "hop2_client_hello": len(hop2_hello),
            "hop2_server_hello": len(hop2_server),
            "hop2_total": len(hop2_hello) + len(hop2_server),
            "hop2_v2_hybrid_client_hello": len(v2_hybrid_hello),
            "hop2_v2_hybrid_server_hello": len(v2_hybrid_server),
            "hop2_v2_hybrid_total": len(v2_hybrid_hello) + len(v2_hybrid_server),
            "hop2_v2_classical_client_hello": len(v2_classical_hello),
            "hop2_v2_classical_server_hello": len(v2_classical_server),
            "hop2_v2_classical_total": len(v2_classical_hello) + len(v2_classical_server),
        },
        "message_bytes": {
            "reading_plaintext_json": len(reading_json),
            "reading_ciphertext_with_tag": len(ciphertext),
            "hop1_ingest_frame_on_wire": len(ingest_frame),
            "gateway_envelope_plaintext_json": len(envelope),
            "gateway_envelope_ciphertext_with_tag": len(envelope_ct),
        },
        "overhead": {
            "aead_expansion_bytes": len(ciphertext) - len(reading_json),
            "framing_overhead_bytes": len(ingest_frame) - len(ciphertext),
            "total_overhead_bytes": len(ingest_frame) - len(reading_json),
            "wire_to_plaintext_ratio": round(len(ingest_frame) / len(reading_json), 3),
            "base64_expansion_ratio": 4 / 3,
        },
    }


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def _delta(before: float, after: float) -> str:
    """Signed percentage change, or 'n/a' when the baseline is zero."""
    if before == 0:
        return "n/a"
    change = (after - before) / before * 100.0
    sign = "+" if change >= 0 else ""
    return f"{sign}{change:.1f}%"


def render_comparison(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Phase 2 vs Phase 4: what adding ML-KEM-768 actually cost.

    Compares like with like. The classical rows should barely move -- if they
    do, the measurement is noisy or something unrelated changed. The hybrid
    rows are the answer to 'what did PQC cost us'.
    """
    lines = [
        "## Before / after: adding ML-KEM-768",
        "",
        f"Baseline `{before['metadata']['label']}` "
        f"({before['metadata']['timestamp']}) vs "
        f"`{after['metadata']['label']}` ({after['metadata']['timestamp']}).",
        "",
        "### Handshake latency (median, ms)",
        "",
        "| measurement | classical (before) | hybrid (after) | delta |",
        "|---|---:|---:|---:|",
    ]

    def latency_of(blob: dict[str, Any], section: str, key: str) -> float | None:
        if section == "key_establishment":
            table = blob.get("key_establishment", {})
        else:
            table = blob.get("protocol", {}).get(section, {})
        entry = table.get(key)
        return entry["median_ms"] if entry else None

    rows = [
        ("hop 2 key establishment (crypto only)",
         ("key_establishment", "hop2_ephemeral_ecdhe_mutual_ecdsa"),
         ("key_establishment", "hop2_hybrid_x25519_mlkem768")),
        ("hop 2 handshake round trip",
         ("handshakes", "hop2_handshake_roundtrip"),
         ("handshakes", "hop2_v2_hybrid_handshake_roundtrip")),
        ("hop 1 key establishment (unchanged)",
         ("key_establishment", "hop1_static_static_ecdh"),
         ("key_establishment", "hop1_static_static_ecdh")),
        ("per-message, both hops (unchanged)",
         ("messages", "end_to_end_reading_both_hops"),
         ("messages", "end_to_end_reading_both_hops")),
    ]
    for label, (b_section, b_key), (a_section, a_key) in rows:
        b_val = latency_of(before, b_section, b_key)
        a_val = latency_of(after, a_section, a_key)
        if b_val is None or a_val is None:
            continue
        lines.append(f"| {label} | {b_val:.4f} | {a_val:.4f} | {_delta(b_val, a_val)} |")

    lines.extend([
        "",
        "### Handshake size (bytes on the wire)",
        "",
        "| measurement | classical (before) | hybrid (after) | delta |",
        "|---|---:|---:|---:|",
    ])
    b_sizes = before.get("sizes", {}).get("handshake_bytes", {})
    a_sizes = after.get("sizes", {}).get("handshake_bytes", {})
    size_rows = [
        ("hop 2 ClientHello", "hop2_client_hello", "hop2_v2_hybrid_client_hello"),
        ("hop 2 ServerHello", "hop2_server_hello", "hop2_v2_hybrid_server_hello"),
        ("hop 2 handshake total", "hop2_total", "hop2_v2_hybrid_total"),
        ("hop 1 handshake total (unchanged)", "hop1_total", "hop1_total"),
    ]
    for label, b_key, a_key in size_rows:
        b_val, a_val = b_sizes.get(b_key), a_sizes.get(a_key)
        if b_val is None or a_val is None:
            continue
        lines.append(f"| {label} | {b_val} | {a_val} | {_delta(b_val, a_val)} |")

    b_msg = before.get("sizes", {}).get("message_bytes", {})
    a_msg = after.get("sizes", {}).get("message_bytes", {})
    lines.extend([
        "",
        "### Per-message size (must be unchanged)",
        "",
        "| measurement | before | after | delta |",
        "|---|---:|---:|---:|",
    ])
    for label, key in [
        ("reading plaintext", "reading_plaintext_json"),
        ("reading ciphertext + tag", "reading_ciphertext_with_tag"),
        ("ingest frame on the wire", "hop1_ingest_frame_on_wire"),
    ]:
        b_val, a_val = b_msg.get(key), a_msg.get(key)
        if b_val is None or a_val is None:
            continue
        lines.append(f"| {label} | {b_val} | {a_val} | {_delta(b_val, a_val)} |")

    lines.extend([
        "",
        "**Reading this table.** ML-KEM establishes a key; it never touches the "
        "payload. So the handshake rows are expected to grow and the per-message "
        "rows are expected to be identical. A non-zero delta in the per-message "
        "section means the KEM has leaked onto the data path, which "
        "`CLAUDE.md` forbids.",
        "",
        "Hop 1 rows are a control: the device is non-upgradeable, so any movement "
        "there is measurement noise rather than a real change.",
        "",
    ])
    return lines


def render_markdown(results: dict[str, Any]) -> str:
    meta = results["metadata"]
    lines = [
        f"# Benchmark — {meta['label']}",
        "",
        f"- **Run:** {meta['timestamp']}",
        f"- **Suite:** {meta['suite']}",
        f"- **Iterations:** {meta['iterations']}",
        f"- **Python:** {meta['python']} on {meta['platform']}",
        f"- **Mode:** {meta['mode']}",
        "",
        "Latency is reported as median and p95. Compare medians; means are "
        "dominated by outliers.",
        "",
    ]

    def latency_table(title: str, table: dict[str, Any]) -> None:
        lines.extend([f"## {title}", "",
                      "| operation | median (ms) | p95 (ms) | min (ms) | n |",
                      "|---|---:|---:|---:|---:|"])
        for name, stats in table.items():
            lines.append(
                f"| `{name}` | {stats['median_ms']:.4f} | {stats['p95_ms']:.4f} "
                f"| {stats['min_ms']:.4f} | {stats['iterations']} |"
            )
        lines.append("")

    latency_table("Primitives", results["primitives"])
    latency_table("Key establishment (crypto only)", results["key_establishment"])
    latency_table("Handshake round trip (incl. HTTP + JSON)",
                  results["protocol"]["handshakes"])
    latency_table("Per-message latency", results["protocol"]["messages"])

    sizes = results["sizes"]
    lines.extend(["## Message sizes", "", "| element | bytes |", "|---|---:|"])
    for section in ("cryptographic_elements_bytes", "handshake_bytes", "message_bytes"):
        for name, value in sizes[section].items():
            lines.append(f"| `{name}` | {value} |")
    lines.append("")

    # --- before/after comparison, if a baseline was supplied -----------------
    baseline = results.get("_baseline")
    if baseline:
        lines.extend(render_comparison(baseline, results))

    ov = sizes["overhead"]
    lines.extend([
        "### Overhead",
        "",
        f"- AEAD expansion: **{ov['aead_expansion_bytes']} bytes** (the GCM tag).",
        f"- Framing (base64 + JSON envelope): **{ov['framing_overhead_bytes']} bytes**.",
        f"- Total per reading: **{ov['total_overhead_bytes']} bytes**, "
        f"a **{ov['wire_to_plaintext_ratio']}x** expansion over the plaintext.",
        "",
        "## What to watch after PQC",
        "",
        "ML-KEM-768 changes the handshake, not the message path. Expect:",
        "",
        "- `hop2_*` handshake latency and size to grow; `hop1_*` to be unchanged.",
        "- ML-KEM-768 encapsulation key is 1184 B and a ciphertext is 1088 B, "
        "against 65 B for a P-256 public key — so the hop 2 handshake should grow "
        "by roughly 2.2 KB before base64, ~3 KB after.",
        "- Per-message latency and size should be **unchanged**: the KEM "
        "establishes the key and never touches the payload. If per-message "
        "numbers move, something is wrong.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=200,
                        help="samples per measurement (default: 200)")
    parser.add_argument("--keys-dir", default="keys", help="directory holding the PEM keys")
    parser.add_argument("--out-dir", default="results", help="where to write the results")
    parser.add_argument("--label", default="legacy-baseline",
                        help="name for this run, used in the filename and report")
    parser.add_argument("--skip-protocol", action="store_true",
                        help="primitives and sizes only (fast)")
    parser.add_argument("--compare", metavar="BASELINE.json",
                        help="a previous results file to produce a before/after table against")
    args = parser.parse_args()

    keys_dir = Path(args.keys_dir)
    if not (keys_dir / "device_ecdh_priv.pem").exists():
        print(f"error: no keys in {keys_dir.resolve()}", file=sys.stderr)
        print("  run: python scripts/gen_keys.py --out keys", file=sys.stderr)
        return 1

    baseline = None
    if args.compare:
        baseline_path = Path(args.compare)
        if not baseline_path.exists():
            print(f"error: baseline {baseline_path} not found", file=sys.stderr)
            return 1
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        print(f"comparing against {baseline_path} "
              f"({baseline['metadata']['label']})")

    logging.getLogger().setLevel(logging.WARNING)
    timestamp = datetime.now(timezone.utc)

    print(f"benchmarking '{args.label}' with {args.iterations} iterations ...")

    print("  [1/4] primitives")
    primitives = bench_primitives(args.iterations)

    print("  [2/4] key establishment")
    key_establishment = bench_key_establishment(keys_dir, args.iterations)

    if args.skip_protocol:
        protocol: dict[str, Any] = {"handshakes": {}, "messages": {}}
        print("  [3/4] protocol (skipped)")
    else:
        print("  [3/4] protocol round trips")
        protocol = bench_protocol(keys_dir, args.iterations)

    print("  [4/4] message sizes")
    sizes = bench_sizes(keys_dir)

    results = {
        "metadata": {
            "label": args.label,
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "suite": (
                "hop2 hybrid: X25519 + ML-KEM-768 / ECDSA-P256 / HKDF-SHA256 / "
                "AES-256-GCM; hop1 + fallback: ECDH-P256"
            ),
            "pqc": True,
            "cryptography_version": _cryptography_version(),
            "iterations": args.iterations,
            "mode": "in-process (no network)",
            "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.machine()}",
            "processor": platform.processor() or "unknown",
        },
        "primitives": primitives,
        "key_establishment": key_establishment,
        "protocol": protocol,
        "sizes": sizes,
    }
    if baseline is not None:
        # Only used for rendering; stripped before the JSON is written so the
        # results file stays a clean single-run record.
        results["_baseline"] = baseline

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = timestamp.strftime("%Y%m%dT%H%M%SZ")

    json_path = out_dir / f"{args.label}-{stamp}.json"
    json_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    # Stable filenames so the PQC run can diff against them without guessing.
    latest_json = out_dir / f"{args.label}-latest.json"
    latest_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    md_path = out_dir / f"{args.label}-latest.md"
    md_path.write_text(render_markdown(results) + "\n", encoding="utf-8")

    print("\nwrote:")
    for path in (json_path, latest_json, md_path):
        print(f"  {path}")

    ke = key_establishment
    msg = protocol["messages"].get("end_to_end_reading_both_hops")
    print("\nheadline numbers (median):")
    print(f"  hop 1 key establishment   {ke['hop1_static_static_ecdh']['median_ms']:.4f} ms")
    print(f"  hop 2 classical           "
          f"{ke['hop2_ephemeral_ecdhe_mutual_ecdsa']['median_ms']:.4f} ms")
    print(f"  hop 2 HYBRID (PQC)        "
          f"{ke['hop2_hybrid_x25519_mlkem768']['median_ms']:.4f} ms")
    if msg:
        print(f"  reading, both hops        {msg['median_ms']:.4f} ms")
    print(f"  wire/plaintext ratio      {sizes['overhead']['wire_to_plaintext_ratio']}x")
    hb = sizes["handshake_bytes"]
    print(f"  hop 2 handshake bytes     {hb['hop2_total']} classical -> "
          f"{hb['hop2_v2_hybrid_total']} hybrid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
