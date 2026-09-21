#!/usr/bin/env python3
"""Demonstrate each migration phase from docs/MIGRATION.md, in process.

Runs the real gateway and cloud apps with different PQC policies and prints
what actually happens at each phase -- which suite is negotiated, what gets
refused, and what the metrics say.

    python scripts/demo_phases.py             # all phases
    python scripts/demo_phases.py --phase 2   # just one

No Docker required. For the containerised equivalent see the compose variables
CLOUD_PQC_POLICY and GATEWAY_PQC_POLICY, e.g.

    CLOUD_PQC_POLICY=prefer GATEWAY_PQC_POLICY=prefer docker compose up
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from services.cloud.main import create_app as create_cloud_app  # noqa: E402
from services.common import cryptoutil as cu  # noqa: E402
from services.common.handshake import HandshakeError  # noqa: E402
from services.common.suites import Policy  # noqa: E402
from services.common.wire import PROTOCOL, b64e  # noqa: E402
from services.gateway.cloud_client import CloudClient, DowngradeRejected  # noqa: E402

GATEWAY_ID = "gw-01"

GREEN, RED, YELLOW, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"
)


def envelope(date: str = "2024-01-01") -> dict:
    return {
        "gateway_id": GATEWAY_ID,
        "device_id": "device-berlin-01",
        "reading": {"date": date, "temp_max_c": 7.4, "temp_min_c": 3.4,
                    "precip_mm": 1.8, "wind_max_kmh": 19.7},
        "received_at": "2026-09-21T10:00:02Z",
        "device_hop": {"verified": True, "suite": "ECDH-P256-static-static+AES-256-GCM"},
    }


def build(keys_dir: Path, cloud_policy: Policy, gateway_policy: Policy):
    cloud_app = create_cloud_app(
        keys_dir=str(keys_dir), db_path=":memory:", policy=cloud_policy
    )
    cloud_http = TestClient(cloud_app, base_url="http://cloud")
    client = CloudClient(
        base_url="http://cloud",
        gateway_id=GATEWAY_ID,
        signing_key=cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem"),
        cloud_public_key=cu.load_public_key(keys_dir / "cloud_ecdsa_pub.pem"),
        log=logging.getLogger("demo"),
        http_client=cloud_http,
        policy=gateway_policy,
    )
    return cloud_http, client


def header(number: str, title: str) -> None:
    print(f"\n{BOLD}{'=' * 74}{RESET}")
    print(f"{BOLD}PHASE {number}: {title}{RESET}")
    print(f"{BOLD}{'=' * 74}{RESET}")


def show(label: str, value: str, good: bool | None = None) -> None:
    colour = "" if good is None else (GREEN if good else RED)
    print(f"  {label:<34} {colour}{value}{RESET}")


def legacy_v1_hello(keys_dir: Path) -> dict:
    """A ClientHello from an un-upgraded, pre-PQC gateway."""
    from services.common.handshake import hop2_client_transcript

    signing = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")
    nonce = cu.random_bytes(16)
    eph_pub = cu.public_key_to_bytes(cu.generate_private_key().public_key())
    return {
        "protocol": PROTOCOL, "hop": "gateway-cloud", "client_id": GATEWAY_ID,
        "client_nonce": b64e(nonce), "eph_pub": b64e(eph_pub),
        "sig": b64e(cu.sign(signing, hop2_client_transcript(GATEWAY_ID, nonce, eph_pub))),
    }


def phase_0(keys_dir: Path) -> None:
    header("0", "Baseline -- classical only (the 'before' state)")
    print("  Cloud and gateway both pinned to classical-only.\n")

    cloud_http, client = build(keys_dir, Policy.CLASSICAL_ONLY, Policy.CLASSICAL_ONLY)
    client.send(envelope())

    show("negotiated suite", str(client.suite), good=False)
    show("post-quantum", "NO -- vulnerable to harvest-now-decrypt-later", good=False)
    show("pqc_fraction", str(cloud_http.get("/stats").json()["pqc"]["pqc_fraction"]),
         good=False)
    client.close()
    cloud_http.close()


def phase_1(keys_dir: Path) -> None:
    header("1", "Hybrid available, policy=prefer -- observe, do not enforce")
    print("  Both sides prefer PQC. A legacy peer still works, loudly.\n")

    cloud_http, client = build(keys_dir, Policy.PREFER, Policy.PREFER)
    client.send(envelope())
    show("upgraded gateway negotiates", str(client.suite), good=True)

    # An un-upgraded gateway arriving at the same cloud.
    response = cloud_http.post("/handshake", json=legacy_v1_hello(keys_dir))
    show("legacy v1 gateway", f"HTTP {response.status_code} -- still served", good=None)

    stats = cloud_http.get("/stats").json()["pqc"]
    show("handshakes_hybrid", str(stats["handshakes_hybrid"]), good=True)
    show("handshakes_classical", str(stats["handshakes_classical"]), good=False)
    show("pqc_fraction", str(stats["pqc_fraction"]), good=None)
    print(f"\n  {YELLOW}Exit criterion: pqc_fraction == 1.0 for 7 days.{RESET}")
    client.close()
    cloud_http.close()


def phase_2(keys_dir: Path) -> None:
    header("2", "policy=require -- classical is refused")
    print("  The cloud now enforces PQC. This is the forcing function.\n")

    cloud_http, client = build(keys_dir, Policy.REQUIRE, Policy.PREFER)
    client.send(envelope())
    show("upgraded gateway", str(client.suite), good=True)

    response = cloud_http.post("/handshake", json=legacy_v1_hello(keys_dir))
    show("legacy v1 gateway",
         f"HTTP {response.status_code} {response.json().get('detail')}", good=True)

    # A gateway that has been rolled back to classical-only.
    rolled_back_cloud, rolled_back = build(keys_dir, Policy.REQUIRE, Policy.CLASSICAL_ONLY)
    try:
        rolled_back.send(envelope())
        show("rolled-back gateway", "ACCEPTED -- this would be a bug", good=False)
    except HandshakeError as exc:
        show("rolled-back gateway", "refused by cloud", good=True)
        print(f"      {str(exc)[:90]}")
    rolled_back.close()
    rolled_back_cloud.close()

    stats = cloud_http.get("/stats").json()["pqc"]
    show("handshakes_downgrade_refused", str(stats["handshakes_downgrade_refused"]),
         good=True)
    show("pqc_fraction", str(stats["pqc_fraction"]), good=True)
    print(f"\n  {YELLOW}Exit criterion: zero downgrade_refused for 7 days "
          f"(the fleet is fully upgraded).{RESET}")
    client.close()
    cloud_http.close()


def phase_downgrade_attack(keys_dir: Path) -> None:
    header("2a", "Active downgrade attempt -- what an attacker gets")
    print("  An on-path attacker strips the hybrid suite from the ClientHello.\n")

    from services.common.handshake import KeyShare, hop2_v2_client_transcript
    from services.common.suites import SUITE_CLASSICAL, SUITE_HYBRID
    from services.common.wire import PROTOCOL_V2

    cloud_http, _ = build(keys_dir, Policy.PREFER, Policy.PREFER)

    signing = cu.load_private_key(keys_dir / "gateway_ecdsa_priv.pem")
    nonce = cu.random_bytes(16)
    x_pub = cu.x25519_public_bytes(cu.generate_x25519_private_key().public_key())
    ek = cu.mlkem768_encapsulation_key_bytes(cu.generate_mlkem768_private_key())
    p256 = cu.public_key_to_bytes(cu.generate_private_key().public_key())

    offered = [SUITE_HYBRID, SUITE_CLASSICAL]
    shares = {
        SUITE_HYBRID: KeyShare(x25519_pub=x_pub, mlkem768_ek=ek),
        SUITE_CLASSICAL: KeyShare(p256_pub=p256),
    }
    hello = {
        "protocol": PROTOCOL_V2, "hop": "gateway-cloud", "client_id": GATEWAY_ID,
        "client_nonce": b64e(nonce), "offered_suites": offered,
        "key_shares": {
            SUITE_HYBRID: {"x25519_pub": b64e(x_pub), "mlkem768_ek": b64e(ek)},
            SUITE_CLASSICAL: {"eph_pub": b64e(p256)},
        },
        "sig": b64e(cu.sign(signing, hop2_v2_client_transcript(
            GATEWAY_ID, nonce, offered, shares))),
    }
    show("honest offer", ", ".join(offered))

    # The attack: remove the hybrid suite, leave the signature alone.
    attacked = dict(hello)
    attacked["offered_suites"] = [SUITE_CLASSICAL]
    attacked["key_shares"] = {SUITE_CLASSICAL: hello["key_shares"][SUITE_CLASSICAL]}
    show("attacker rewrites it to", SUITE_CLASSICAL)

    response = cloud_http.post("/handshake", json=attacked)
    show("cloud responds",
         f"HTTP {response.status_code} {response.json().get('detail')}",
         good=response.status_code == 403)
    print(f"\n  The gateway signs its whole offer, so editing it breaks the signature.")
    print(f"  {YELLOW}Caveat: that signature is ECDSA, which is itself quantum-broken.")
    print(f"  After a CRQC exists this defence fails and only policy=require holds.{RESET}")
    cloud_http.close()


def phase_3(keys_dir: Path) -> None:
    header("3-4", "Hop 1 remains classical -- the honest limitation")
    print("  Hop 2 is post-quantum. Hop 1 is not, and the device cannot change.\n")

    cloud_http, client = build(keys_dir, Policy.REQUIRE, Policy.REQUIRE)
    client.send(envelope())

    show("hop 2 (gateway -> cloud)", f"{client.suite}  POST-QUANTUM", good=True)
    show("hop 1 (device -> gateway)", "ECDH-P256-static-static  CLASSICAL", good=False)
    print(f"\n  {RED}An attacker recording hop 1 today can decrypt it with a future")
    print(f"  quantum computer, whatever hop 2 does. The system as a whole is NOT")
    print(f"  post-quantum until phase 4 replaces the device fleet.{RESET}")
    print(f"\n  {YELLOW}Sunset criteria for classical on hop 1: see docs/MIGRATION.md.{RESET}")
    client.close()
    cloud_http.close()


PHASES = {
    "0": phase_0,
    "1": phase_1,
    "2": phase_2,
    "2a": phase_downgrade_attack,
    "3": phase_3,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--phase", choices=sorted(PHASES), help="run one phase only")
    parser.add_argument("--keys-dir", default="keys")
    args = parser.parse_args()

    keys_dir = Path(args.keys_dir)
    if not (keys_dir / "gateway_ecdsa_priv.pem").exists():
        print(f"error: no keys in {keys_dir.resolve()}", file=sys.stderr)
        print("  run: python scripts/gen_keys.py --out keys", file=sys.stderr)
        return 1

    # Quiet the services; this script narrates for itself.
    logging.getLogger().setLevel(logging.ERROR)
    for name in ("cloud", "gateway", "demo"):
        logging.getLogger(name).setLevel(logging.ERROR)

    selected = [args.phase] if args.phase else sorted(PHASES, key=lambda k: (k[0], k))
    for phase in selected:
        PHASES[phase](keys_dir)

    print(f"\n{BOLD}{'=' * 74}{RESET}")
    print("Full migration plan and sunset criteria: docs/MIGRATION.md")
    print(f"{BOLD}{'=' * 74}{RESET}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
