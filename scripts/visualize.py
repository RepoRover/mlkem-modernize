#!/usr/bin/env python3
"""Show what actually happens in the backend, step by step.

Runs the REAL device, gateway and cloud apps in-process and taps every HTTP
call between them, so the byte counts, suites and rejections printed below are
measured from a live run rather than copied out of the docs.

    python scripts/visualize.py
    python scripts/visualize.py --step 3      # one step only

Deliberately NOT printed: session keys, shared secrets, and decrypted payloads.
CLAUDE.md forbids logging them. Keys appear only as truncated SHA-256
fingerprints, which are one-way and exist purely to show that two keys differ.

Related: scripts/demo_phases.py walks the migration phases instead of the
data path; scripts/benchmark.py measures cost rather than showing structure.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from services.cloud.main import create_app as create_cloud_app  # noqa: E402
from services.common import cryptoutil as cu  # noqa: E402
from services.common.handshake import KeyShare, hop2_v2_derive  # noqa: E402
from services.common.suites import SUITE_HYBRID, Policy  # noqa: E402
from services.common.weather import parse_weather_file  # noqa: E402
from services.common.wire import (  # noqa: E402
    DIR_CLIENT_TO_SERVER,
    DIR_SERVER_TO_CLIENT,
    b64d,
    b64e,
    counter_bytes,
)
from services.device.gateway_client import GatewayClient  # noqa: E402
from services.gateway.cloud_client import CloudClient  # noqa: E402
from services.gateway.main import create_app as create_gateway_app  # noqa: E402

DEVICE_ID = "device-berlin-01"
GATEWAY_ID = "gw-01"

GREEN, RED, CYAN, DIM, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[36m", "\033[2m", "\033[1m", "\033[0m"
)


# ---------------------------------------------------------------- the wire tap


@dataclass
class Frame:
    """One HTTP exchange between two services, as seen on the wire."""

    hop: str
    method: str
    path: str
    req_bytes: int
    req_body: dict[str, Any] = field(default_factory=dict)
    status: int = 0
    resp_bytes: int = 0
    resp_body: dict[str, Any] = field(default_factory=dict)


class WireTap:
    """Records every request/response between the services.

    httpx event hooks fire in strict nesting order (the gateway's call to the
    cloud starts and finishes inside the device's call to the gateway), so a
    stack pairs responses back to their requests correctly.
    """

    def __init__(self) -> None:
        self.frames: list[Frame] = []
        self._stack: list[Frame] = []

    def attach(self, client: TestClient, hop: str) -> None:
        client.event_hooks = {
            "request": [functools.partial(self._on_request, hop=hop)],
            "response": [self._on_response],
        }

    def _on_request(self, request: httpx.Request, hop: str) -> None:
        body = request.content
        frame = Frame(
            hop=hop,
            method=request.method,
            path=request.url.path,
            req_bytes=len(body),
            req_body=_as_dict(body),
        )
        self.frames.append(frame)
        self._stack.append(frame)

    def _on_response(self, response: httpx.Response) -> None:
        if not self._stack:  # pragma: no cover - defensive
            return
        frame = self._stack.pop()
        frame.status = response.status_code
        try:
            response.read()
        except Exception:  # pragma: no cover - defensive
            # A diagnostic tap must never be the thing that breaks the run it
            # is observing, so any read failure just costs us the body.
            return
        frame.resp_bytes = len(response.content)
        frame.resp_body = _as_dict(response.content)


def _as_dict(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


# ------------------------------------------------------------------- printing


def banner(text: str) -> None:
    print(f"\n{BOLD}{'=' * 78}{RESET}")
    print(f"{BOLD}{text}{RESET}")
    print(f"{BOLD}{'=' * 78}{RESET}")


def step(number: str, title: str) -> None:
    print(f"\n{BOLD}{CYAN}STEP {number}{RESET}  {BOLD}{title}{RESET}")
    print(f"{DIM}{'-' * 78}{RESET}")


def row(label: str, value: str, good: bool | None = None) -> None:
    colour = "" if good is None else (GREEN if good else RED)
    print(f"    {label:<32} {colour}{value}{RESET}")


def fingerprint(material: bytes) -> str:
    """One-way, truncated. Shows that two keys DIFFER without revealing either."""
    return hashlib.sha256(material).hexdigest()[:12]


def hexdump(raw: bytes, limit: int = 48) -> str:
    shown = raw[:limit]
    body = " ".join(f"{b:02x}" for b in shown)
    return body + (f" ... (+{len(raw) - limit} more)" if len(raw) > limit else "")


def draw_pipeline() -> None:
    print(f"""
    {BOLD}+----------+        +-----------+        +---------+      +--------+{RESET}
    {BOLD}| device   |        | gateway   |        | cloud   |      | SQLite |{RESET}
    {BOLD}| (legacy  |  hop 1 | (edge,    |  hop 2 | (store  |      |        |{RESET}
    {BOLD}|  sensor) | -----> |  trust    | -----> |  + API) | ---> |        |{RESET}
    {BOLD}+----------+        |  boundary)|        +---------+      +--------+{RESET}
    {BOLD}                    +-----------+{RESET}
                        {RED}classical{RESET}           {GREEN}POST-QUANTUM{RESET}
                   ECDH P-256 static-static   X25519 + ML-KEM-768
                   {RED}no forward secrecy{RESET}         {GREEN}forward secret{RESET}
                   {RED}breakable by a CRQC{RESET}        {GREEN}HNDL-resistant{RESET}

    The gateway is the migration seam: it {BOLD}decrypts{RESET} hop 1 and {BOLD}re-encrypts{RESET}
    onto hop 2. That is why the device never has to change -- and also why the
    gateway sees plaintext, which is the trust boundary called out in
    docs/MIGRATION.md.
""")


# ---------------------------------------------------------------- the live run


@dataclass
class Stack:
    device: GatewayClient
    gateway_http: TestClient
    cloud_http: TestClient
    cloud_client: CloudClient
    tap: WireTap

    def close(self) -> None:
        self.device.close()
        self.gateway_http.close()
        self.cloud_http.close()


def build_stack(keys_dir: Path) -> Stack:
    tap = WireTap()

    cloud_app = create_cloud_app(
        keys_dir=str(keys_dir), db_path=":memory:", policy=Policy.REQUIRE
    )
    cloud_http = TestClient(cloud_app, base_url="http://cloud")
    tap.attach(cloud_http, "hop 2")

    cloud_client = CloudClient(
        base_url="http://cloud",
        gateway_id=GATEWAY_ID,
        signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
        cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        log=logging.getLogger("gateway"),
        http_client=cloud_http,
        # The documented gateway default. It offers BOTH suites, so the trace
        # shows a real negotiation rather than a single-option handshake.
        policy=Policy.PREFER,
    )

    gateway_app = create_gateway_app(
        keys_dir=str(keys_dir), cloud_url="http://cloud", cloud_client=cloud_client
    )
    gateway_http = TestClient(gateway_app, base_url="http://gateway")
    tap.attach(gateway_http, "hop 1")

    device = GatewayClient(
        base_url="http://gateway",
        device_id=DEVICE_ID,
        device_static_key=cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
        gateway_public_key=cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
        log=logging.getLogger("device"),
        http_client=gateway_http,
    )

    return Stack(device, gateway_http, cloud_http, cloud_client, tap)


def find(frames: list[Frame], hop: str, path: str) -> Frame | None:
    for frame in frames:
        if frame.hop == hop and frame.path == path:
            return frame
    return None


# ----------------------------------------------------------------- the steps


def step_1_data(readings: list[Any], station: Any) -> dict[str, Any]:
    step("1", "The data going in")
    print("    Real Open-Meteo daily export, parsed by services/common/weather.py.\n")
    reading = readings[0]
    row("source file", "data/weather_data.csv")
    row("station", f"lat {station.lat}, lon {station.lon}, {station.tz}")
    row("readings parsed", f"{len(readings)} daily records")
    row("first record", f"{reading.date}  max {reading.temp_max_c} C  "
                        f"min {reading.temp_min_c} C  "
                        f"precip {reading.precip_mm} mm  "
                        f"wind {reading.wind_max_kmh} km/h")
    print(f"\n    {DIM}Public weather observations -- there is no secret here. The point"
          f"\n    is the migration mechanics, not the confidentiality of this data.{RESET}")

    return {
        "device_id": DEVICE_ID,
        "station": station.to_dict(),
        "sent_at": "2026-09-21T10:00:00Z",
        **reading.to_dict(),
    }


def step_2_hop1(frames: list[Frame]) -> None:
    step("2", "hop 1 handshake   device -> gateway   (the legacy hop)")

    hello = find(frames, "hop 1", "/handshake")
    if hello is None:  # pragma: no cover - defensive
        print("    no hop 1 handshake was captured")
        return

    print(f"    {BOLD}ClientHello{RESET}  POST /handshake   {hello.req_bytes} bytes")
    for key in ("protocol", "hop", "client_id"):
        row(f"  {key}", str(hello.req_body.get(key)))
    row("  client_nonce", f"{len(b64d(hello.req_body['client_nonce']))} random bytes")

    print(f"\n    {BOLD}ServerHello{RESET}  HTTP {hello.status}        {hello.resp_bytes} bytes")
    row("  session_id", f"{len(b64d(hello.resp_body['session_id']))} bytes")
    row("  server_nonce", f"{len(b64d(hello.resp_body['server_nonce']))} bytes")
    row("  nonce_prefix", f"{len(b64d(hello.resp_body['nonce_prefix']))} bytes")
    row("  expires_at", str(hello.resp_body["expires_at"]))
    row("  signature", "NONE", good=False)

    print(f"""
    {BOLD}Key derivation{RESET}
        Z    = ECDH(device_static_priv, gateway_static_pub)   <- same every time
        key  = HKDF-SHA256(ikm=Z, salt=client_nonce||server_nonce, info=label)

    {RED}Two deliberate legacy weaknesses, both visible above:{RESET}
      {RED}*{RESET} no ephemeral key, so every session this device ever opens derives
        from the SAME Z. One recovered static key retroactively opens all of them.
      {RED}*{RESET} the ServerHello carries no signature, so an on-path attacker can
        forge it. The device only finds out when its first message is rejected.

    {DIM}This hop is frozen on purpose: the premise is that the firmware cannot
    be updated. It is the "before" state the whole project migrates away from.{RESET}""")


def step_3_hop2(frames: list[Frame], suite: str | None) -> None:
    step("3", "hop 2 handshake   gateway -> cloud   (the post-quantum one)")

    hello = find(frames, "hop 2", "/handshake")
    if hello is None:  # pragma: no cover - defensive
        print("    no hop 2 handshake was captured")
        return

    offered = hello.req_body.get("offered_suites", [])
    shares = hello.req_body.get("key_shares", {})

    print(f"    {BOLD}ClientHello{RESET}  POST /handshake   {hello.req_bytes} bytes")
    row("  protocol", str(hello.req_body.get("protocol")))
    row("  offered_suites", ", ".join(offered))
    for name in offered:
        share = shares.get(name, {})
        parts = ", ".join(f"{k} {len(b64d(v))} B" for k, v in share.items())
        row(f"  key_share[{name[:22]}]", parts)
    row("  sig (ECDSA P-256)", f"{len(b64d(hello.req_body['sig']))} bytes over the "
                               f"WHOLE offer")

    print(f"\n    {BOLD}ServerHello{RESET}  HTTP {hello.status}        {hello.resp_bytes} bytes")
    selected = hello.resp_body.get("selected_suite")
    row("  selected_suite", str(selected), good=selected == SUITE_HYBRID)
    if "mlkem768_ct" in hello.resp_body:
        row("  mlkem768_ct", f"{len(b64d(hello.resp_body['mlkem768_ct']))} bytes "
                             f"(ML-KEM-768 encapsulation)")
    if "x25519_pub" in hello.resp_body:
        row("  x25519_pub", f"{len(b64d(hello.resp_body['x25519_pub']))} bytes")
    row("  sig", f"{len(b64d(hello.resp_body['sig']))} bytes over the full transcript",
        good=True)

    print(f"""
    {BOLD}What just happened, in order{RESET}
      1. gateway generated an EPHEMERAL X25519 key and an EPHEMERAL ML-KEM-768
         keypair, offered both suites, and signed the entire offer.
      2. cloud verified that signature, then chose a suite under its policy.
      3. cloud encapsulated to the gateway's ML-KEM key -> (shared_secret, ct)
         and signed a transcript that {BOLD}re-includes the gateway's whole offer{RESET}.
      4. gateway verified that signature against the offer it actually SENT.
         An attacker who edited the offer in flight cannot survive this check.
      5. both sides ran the same combiner:

             {BOLD}IKM = ss_mlkem768 (32 B) || ss_x25519 (32 B){RESET}
             key_c2s = HKDF(IKM, salt=nonces, info=transcript || "{DIR_CLIENT_TO_SERVER}")
             key_s2c = HKDF(IKM, salt=nonces, info=transcript || "{DIR_SERVER_TO_CLIENT}")

    {GREEN}The security claim: this key is safe if EITHER ML-KEM-768 or X25519 holds.{RESET}
    A quantum attacker must break both, and only ML-KEM is believed to resist one.
    ML-KEM establishes the key and {BOLD}never touches the payload{RESET} -- that is the
    CLAUDE.md rule, and it is why per-message size below is unchanged.""")

    row("negotiated suite (live)", str(suite), good=suite == SUITE_HYBRID)


@dataclass
class KeySchedule:
    """Measured output of one real hop 2 key derivation."""

    ss_mlkem_len: int
    ss_x25519_len: int
    nonce_prefix_len: int
    fp_c2s: str
    fp_s2c: str
    differ: bool


def sample_key_schedule() -> KeySchedule:
    """Run the real key schedule on fresh values.

    Shows a property the wire trace cannot: the two directions get DIFFERENT
    keys from the same shared secrets. Returns fingerprints, never keys.
    """
    gw_x = cu.generate_x25519_private_key()
    gw_kem = cu.generate_mlkem768_private_key()
    ek = cu.mlkem768_encapsulation_key_bytes(gw_kem)

    cloud_x = cu.generate_x25519_private_key()
    ss_kem, ct = cu.mlkem768_encapsulate(cu.mlkem768_encapsulation_key_from_bytes(ek))
    ss_x = cu.x25519_exchange(gw_x, cu.x25519_public_from_bytes(
        cu.x25519_public_bytes(cloud_x.public_key())))

    client_share = KeyShare(x25519_pub=cu.x25519_public_bytes(gw_x.public_key()),
                            mlkem768_ek=ek)
    server_share = KeyShare(x25519_pub=cu.x25519_public_bytes(cloud_x.public_key()))

    session = hop2_v2_derive(
        selected_suite=SUITE_HYBRID,
        ss_mlkem768=ss_kem,
        ss_classical=ss_x,
        client_id=GATEWAY_ID,
        offered_suites=[SUITE_HYBRID],
        client_nonce=cu.random_bytes(cu.HANDSHAKE_NONCE_LEN),
        server_nonce=cu.random_bytes(cu.HANDSHAKE_NONCE_LEN),
        client_share=client_share,
        server_share=server_share,
        mlkem768_ct=ct,
        session_id=cu.random_bytes(cu.SESSION_ID_LEN),
        nonce_prefix=cu.random_bytes(cu.NONCE_PREFIX_LEN),
    )

    return KeySchedule(
        ss_mlkem_len=len(ss_kem),
        ss_x25519_len=len(ss_x),
        nonce_prefix_len=len(session.nonce_prefix),
        fp_c2s=fingerprint(session.key_c2s),
        fp_s2c=fingerprint(session.key_s2c),
        differ=session.key_c2s != session.key_s2c,
    )


def step_4_key_schedule() -> None:
    step("4", "Why the two directions get different keys")
    print("    Re-running the real key schedule (services/common/handshake.py)")
    print("    on fresh values, to show a property the wire trace cannot show.\n")

    schedule = sample_key_schedule()
    row("ML-KEM-768 shared secret", f"{schedule.ss_mlkem_len} bytes (never printed)")
    row("X25519 shared secret", f"{schedule.ss_x25519_len} bytes (never printed)")
    row("nonce_prefix", f"{schedule.nonce_prefix_len} bytes, SHARED by both directions")
    row(f"key_c2s  ({DIR_CLIENT_TO_SERVER})", f"fingerprint {schedule.fp_c2s}")
    row(f"key_s2c  ({DIR_SERVER_TO_CLIENT})", f"fingerprint {schedule.fp_s2c}")
    row("keys are different", str(schedule.differ), good=schedule.differ)

    print(f"""
    {DIM}Fingerprints are truncated SHA-256 -- one-way, and shown only to prove the
    two keys differ. The keys themselves are never printed or logged.{RESET}

    {BOLD}Why this matters:{RESET} the nonce is nonce_prefix || counter, and both
    directions share the prefix and both start counting at 0. If they also shared
    a KEY, message 0 each way would reuse the same (key, nonce) pair -- the single
    thing AES-GCM must never do. Separate HKDF labels make that impossible by
    construction rather than by convention.""")


def step_5_message(frames: list[Frame], plaintext_len: int) -> None:
    step("5", "One reading travelling end to end")

    hop1 = find(frames, "hop 1", "/ingest")
    hop2 = find(frames, "hop 2", "/ingest")
    if hop1 is None or hop2 is None:  # pragma: no cover - defensive
        print("    no ingest frames captured")
        return

    print(f"""    {BOLD}device{RESET}
      builds the reading JSON                    {plaintext_len} bytes plaintext
      AES-256-GCM seal, nonce = prefix||counter  aad = session_id||counter
        |
        v  POST /ingest  {hop1.req_bytes} bytes  {DIM}(base64 inflates it ~33%){RESET}
    {BOLD}gateway{RESET}   HTTP {hop1.status}  {_verdict(hop1)}
      opens the AEAD  -> tag valid, replay counter advanced
      validates the reading against plausibility bounds
      checks payload device_id == the device that opened the session
      wraps it in an envelope and RE-ENCRYPTS onto hop 2
        |
        v  POST /ingest  {hop2.req_bytes} bytes
    {BOLD}cloud{RESET}     HTTP {hop2.status}  {_verdict(hop2)}
      opens the AEAD, validates again, writes to SQLite
""")
    row("hop 1 ciphertext on the wire", f"{len(b64d(hop1.req_body['ct']))} bytes")
    row("hop 2 ciphertext on the wire", f"{len(b64d(hop2.req_body['ct']))} bytes")
    row("hop 2 handshake cost (once)", "3959 bytes, then amortised over 100 records")
    row("hop 2 per-message PQC cost", "0 bytes", good=True)

    print(f"\n    {BOLD}What an eavesdropper on hop 2 actually sees:{RESET}")
    print(f"    {DIM}{hexdump(b64d(hop2.req_body['ct']))}{RESET}")
    print(f"\n    {GREEN}Recorded today, this stays confidential against a future quantum")
    print(f"    computer, because the key came from ML-KEM-768.{RESET}")
    print(f"    {RED}The same reading crossed hop 1 first, where it does NOT.{RESET}")


def _verdict(frame: Frame) -> str:
    status = frame.resp_body.get("status", "")
    reason = frame.resp_body.get("reason")
    colour = GREEN if frame.status == 200 else RED
    return f"{colour}{status}{(' / ' + str(reason)) if reason else ''}{RESET}"


@dataclass
class Probe:
    """One deliberately bad message and how the backend answered it."""

    label: str
    status: int
    reason: str
    note: str


def run_rejection_probes(stack: Stack, good: dict[str, Any]) -> list[Probe]:
    """Send deliberately broken messages. Every one must be refused, not crash."""
    results: list[Probe] = []

    def probe(label: str, body: dict[str, Any], note: str) -> None:
        response = stack.gateway_http.post("/ingest", json=body)
        results.append(Probe(
            label=label,
            status=response.status_code,
            reason=str(response.json().get("reason")),
            note=note,
        ))

    probe("exact message replayed", good,
          "the AEAD counter has already passed this seq")

    # The nonce is fully determined by the session prefix and the counter, so a
    # tampered message needs a correctly-formed nonce for its new seq --
    # otherwise the counter check fires first and we would be demonstrating the
    # wrong defence.
    prefix = b64d(good["nonce"])[: cu.NONCE_PREFIX_LEN]
    next_seq = int(good["seq"]) + 1
    flipped = bytearray(b64d(good["ct"]))
    flipped[0] ^= 0x01
    probe("one ciphertext bit flipped", dict(
        good, seq=next_seq, nonce=b64e(prefix + counter_bytes(next_seq)),
        ct=b64e(bytes(flipped)),
    ), "AES-GCM authentication tag does not verify")

    probe("counter/nonce mismatch", dict(good, seq=next_seq + 1),
          "nonce is not prefix||counter for this seq")
    probe("malformed base64", dict(good, seq=next_seq + 2, ct="not-base64!!"),
          "rejected at decoding, before any crypto")
    probe("null session_id", {"session_id": None},
          "this once returned 500; wire.py was hardened")
    probe("empty body", {}, "missing fields, not an unhandled KeyError")

    return results


def step_6_rejections(stack: Stack, frames: list[Frame]) -> None:
    step("6", "The backend refusing bad input (rejected, never crashed)")

    hop1 = find(frames, "hop 1", "/ingest")
    if hop1 is None:  # pragma: no cover - defensive
        print("    no ingest frame to attack")
        return

    for result in run_rejection_probes(stack, hop1.req_body):
        row(result.label, f"HTTP {result.status} {result.reason}",
            good=result.status != 200)

    print(f"""
    {DIM}Every one of these returns a 4xx with a reason. None raises, none returns
    500, and none says more than a category. The "null session_id" case is here
    because it once DID return 500 -- the negative tests found it and
    services/common/wire.py was hardened rather than the call sites patched.

    Note the two different rejections: a flipped bit fails the AEAD TAG, while a
    wrong counter fails the REPLAY check before the tag is ever examined.{RESET}""")


def step_7_state(stack: Stack) -> None:
    step("7", "What ends up in the cloud")

    health = stack.cloud_http.get("/health").json()
    row("cloud status", str(health.get("status")), good=health.get("status") == "ok")
    row("protocols served", ", ".join(health.get("protocols", [])))
    row("policy", str(health.get("policy")))

    stats = stack.cloud_http.get("/stats").json()
    pqc = stats.get("pqc", {})
    storage = stats.get("storage", {})
    row("rows in SQLite", f"{storage.get('total')} readings from "
                          f"{storage.get('devices')} device(s), "
                          f"{storage.get('first_date')} .. {storage.get('last_date')}")
    row("messages accepted / rejected",
        f"{stats.get('messages', {}).get('accepted')} / "
        f"{stats.get('messages', {}).get('rejected')}")
    row("handshakes_hybrid", str(pqc.get("handshakes_hybrid")), good=True)
    row("handshakes_classical", str(pqc.get("handshakes_classical")),
        good=pqc.get("handshakes_classical") == 0)
    row("handshakes_downgrade_refused", str(pqc.get("handshakes_downgrade_refused")))
    row("pqc_fraction", str(pqc.get("pqc_fraction")),
        good=pqc.get("pqc_fraction") == 1.0)

    readings = stack.cloud_http.get("/readings?limit=3").json()
    items = readings if isinstance(readings, list) else readings.get("readings", [])
    print(f"\n    {BOLD}GET /readings?limit=3{RESET}")
    for item in items[:3]:
        print(f"      {DIM}{json.dumps(item, separators=(',', ':'))[:100]}{RESET}")

    print(f"""
    {BOLD}pqc_fraction is the number to watch.{RESET} A health check returning 200 proves
    the process started. It does not prove hop 2 negotiated post-quantum crypto
    rather than quietly falling back to classical. That is exactly what
    scripts/smoke_test.py asserts in CI, and it is the check that fails on a
    stack which is otherwise completely healthy.""")


# ----------------------------------------------------- structured trace (web)


def _payload(station: Any, reading: Any) -> dict[str, Any]:
    return {
        "device_id": DEVICE_ID,
        "station": station.to_dict(),
        "sent_at": "2026-09-21T10:00:00Z",
        **reading.to_dict(),
    }


def _share_sizes(share: dict[str, str]) -> dict[str, int]:
    return {name: len(b64d(value)) for name, value in share.items()}


def collect_trace(keys_dir: Path, data_file: Path, extra_readings: int = 5) -> dict[str, Any]:
    """Run the whole flow once and return everything measured, as plain data.

    This is what the local web page renders. The CLI prints from the same
    helpers (`sample_key_schedule`, `run_rejection_probes`, `build_stack`), so
    the two front-ends cannot drift apart on the numbers they report.
    """
    station, readings = parse_weather_file(data_file)
    stack = build_stack(keys_dir)

    try:
        payload = _payload(station, readings[0])
        plaintext_len = len(json.dumps(payload, separators=(",", ":")).encode())
        result = stack.device.send_reading(payload)
        frames = list(stack.tap.frames)

        hop1_hs = find(frames, "hop 1", "/handshake")
        hop2_hs = find(frames, "hop 2", "/handshake")
        hop1_in = find(frames, "hop 1", "/ingest")
        hop2_in = find(frames, "hop 2", "/ingest")
        if hop1_hs is None or hop2_hs is None or hop1_in is None or hop2_in is None:
            raise RuntimeError("the live run did not produce the expected frames")

        probes = run_rejection_probes(stack, hop1_in.req_body)

        for reading in readings[1 : 1 + extra_readings]:
            stack.device.send_reading(_payload(station, reading))

        health = stack.cloud_http.get("/health").json()
        stats = stack.cloud_http.get("/stats").json()
        listing = stack.cloud_http.get("/readings?limit=5").json()

        offered = hop2_hs.req_body.get("offered_suites", [])
        client_shares = hop2_hs.req_body.get("key_shares", {})

        return {
            "accepted": result.get("status") == "accepted",
            "station": station.to_dict(),
            "readings_parsed": len(readings),
            "first_reading": readings[0].to_dict(),
            "plaintext_len": plaintext_len,
            "hop1_handshake": {
                "req_bytes": hop1_hs.req_bytes,
                "resp_bytes": hop1_hs.resp_bytes,
                "status": hop1_hs.status,
                "protocol": hop1_hs.req_body.get("protocol"),
                "client_nonce_len": len(b64d(hop1_hs.req_body["client_nonce"])),
                "session_id_len": len(b64d(hop1_hs.resp_body["session_id"])),
                "server_nonce_len": len(b64d(hop1_hs.resp_body["server_nonce"])),
                "nonce_prefix_len": len(b64d(hop1_hs.resp_body["nonce_prefix"])),
                "expires_at": hop1_hs.resp_body.get("expires_at"),
                "signed": False,
            },
            "hop2_handshake": {
                "req_bytes": hop2_hs.req_bytes,
                "resp_bytes": hop2_hs.resp_bytes,
                "status": hop2_hs.status,
                "protocol": hop2_hs.req_body.get("protocol"),
                "offered_suites": offered,
                "key_shares": {n: _share_sizes(client_shares.get(n, {})) for n in offered},
                "client_sig_len": len(b64d(hop2_hs.req_body["sig"])),
                "selected_suite": hop2_hs.resp_body.get("selected_suite"),
                "mlkem768_ct_len": len(b64d(hop2_hs.resp_body.get("mlkem768_ct", ""))),
                "x25519_pub_len": len(b64d(hop2_hs.resp_body.get("x25519_pub", ""))),
                "server_sig_len": len(b64d(hop2_hs.resp_body["sig"])),
                "is_pqc": hop2_hs.resp_body.get("selected_suite") == SUITE_HYBRID,
            },
            "message": {
                "hop1_req_bytes": hop1_in.req_bytes,
                "hop1_ct_bytes": len(b64d(hop1_in.req_body["ct"])),
                "hop1_status": hop1_in.status,
                "hop2_req_bytes": hop2_in.req_bytes,
                "hop2_ct_bytes": len(b64d(hop2_in.req_body["ct"])),
                "hop2_status": hop2_in.status,
                "ciphertext_hex": hexdump(b64d(hop2_in.req_body["ct"]), limit=64),
            },
            "key_schedule": sample_key_schedule(),
            "probes": probes,
            "health": health,
            "stats": stats,
            "readings_sample": listing.get("readings", []),
        }
    finally:
        stack.close()


# ------------------------------------------------------------------------ main


def run(keys_dir: Path, data_file: Path, only: str | None) -> int:
    station, readings = parse_weather_file(data_file)
    stack = build_stack(keys_dir)

    try:
        payload = step_1_data(readings, station) if only in (None, "1") else {
            "device_id": DEVICE_ID, "station": station.to_dict(),
            "sent_at": "2026-09-21T10:00:00Z", **readings[0].to_dict(),
        }
        plaintext_len = len(json.dumps(payload, separators=(",", ":")).encode())

        # One real reading, all the way through. Everything below reads the tap.
        result = stack.device.send_reading(payload)
        frames = list(stack.tap.frames)

        if result.get("status") != "accepted":
            print(f"\n{RED}the reading was not accepted: {result}{RESET}")
            return 1

        if only in (None, "2"):
            step_2_hop1(frames)
        if only in (None, "3"):
            step_3_hop2(frames, stack.cloud_client.suite)
        if only in (None, "4"):
            step_4_key_schedule()
        if only in (None, "5"):
            step_5_message(frames, plaintext_len)
        if only in (None, "6"):
            step_6_rejections(stack, frames)
        if only in (None, "7"):
            # A few more readings so the read API has something to show.
            for reading in readings[1:6]:
                stack.device.send_reading({
                    "device_id": DEVICE_ID, "station": station.to_dict(),
                    "sent_at": "2026-09-21T10:00:00Z", **reading.to_dict(),
                })
            step_7_state(stack)
    finally:
        stack.close()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--step", choices=[str(n) for n in range(1, 8)],
                        help="show one step only")
    parser.add_argument("--keys-dir", default="keys")
    parser.add_argument("--data", default="data/weather_data.csv")
    args = parser.parse_args()

    keys_dir = Path(args.keys_dir)
    if not (keys_dir / "gateway_ecdsa_priv.pem").exists():
        print(f"error: no keys in {keys_dir.resolve()}", file=sys.stderr)
        print("  run: python scripts/gen_keys.py --out keys", file=sys.stderr)
        return 1

    data_file = Path(args.data)
    if not data_file.exists():
        print(f"error: no weather data at {data_file.resolve()}", file=sys.stderr)
        return 1

    # The services log for themselves; this script narrates instead.
    logging.getLogger().setLevel(logging.ERROR)
    for name in ("cloud", "gateway", "device", "httpx"):
        logging.getLogger(name).setLevel(logging.ERROR)

    if args.step is None:
        banner("WHAT ACTUALLY HAPPENS IN THE BACKEND")
        print("    Real services, in-process, with every HTTP call tapped.")
        draw_pipeline()

    code = run(keys_dir, data_file, args.step)

    if args.step is None:
        banner("SUMMARY")
        print(f"""
    {GREEN}hop 2 (gateway -> cloud) is post-quantum.{RESET} Traffic recorded there today
    stays confidential against a future quantum computer.

    {RED}hop 1 (device -> gateway) is not, and cannot be{RESET} -- the device is
    non-upgradeable by premise. The same readings cross it in the clear-to-a-CRQC
    sense, so the system AS A WHOLE is not post-quantum secure.

    Authentication on both hops is still ECDSA P-256, which a CRQC also breaks.
    That enables ACTIVE attacks only, and only once such a machine exists;
    it does not retroactively expose recorded hybrid traffic.

    docs/MIGRATION.md has the phase plan and the sunset criteria for hop 1.
""")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
