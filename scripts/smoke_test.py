#!/usr/bin/env python3
"""Post-deploy smoke test.

Answers one question: is the thing we just deployed actually working, and is it
working *the way we intended* -- not merely responding.

A health endpoint returning 200 proves the process is up. It does not prove the
gateway can reach the cloud, that keys were mounted, or that hop 2 negotiated
post-quantum key establishment rather than silently falling back to classical.
This script checks those too, because those are the failures a deploy actually
introduces: a missing secret, a wrong env var, an unreachable service.

Usage:
    python scripts/smoke_test.py --cloud-url http://127.0.0.1:8000
    python scripts/smoke_test.py --cloud-url ... --expect-readings 5 --timeout 120

Exit code 0 = every check passed. Non-zero = the deploy is not healthy, with the
failing check named on stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

GREEN, RED, YELLOW, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"
)


class SmokeFailure(Exception):
    """A check failed. The message is what gets printed and logged."""


def get_json(url: str, timeout: float = 10.0) -> Any:
    """Fetch and decode JSON, refusing anything that is not plain HTTP(S).

    The URL comes from a CI argument, so the scheme is checked rather than
    trusted: without this, `file:///etc/passwd` or a custom handler would be
    accepted by urlopen. Both ruff (S310) and bandit flag the unguarded call,
    and they are right to -- this is the guard, not a suppression.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SmokeFailure(f"refusing non-HTTP(S) URL scheme {parsed.scheme!r} in {url!r}")

    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        return json.loads(response.read())


def wait_for(url: str, timeout: float, interval: float = 3.0) -> Any:
    """Poll until the endpoint answers or we run out of patience.

    A deploy is not instant, so the first failure is not a real failure. But an
    unbounded wait turns a broken deploy into a hung pipeline, hence the budget.
    """
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return get_json(url)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as exc:
            last = exc
            time.sleep(interval)
    raise SmokeFailure(f"{url} never became available within {timeout:.0f}s (last error: {last})")


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def ok(self, name: str, detail: str = "") -> None:
        self.passed += 1
        print(f"  {GREEN}PASS{RESET}  {name}" + (f"  ({detail})" if detail else ""))

    def fail(self, name: str, detail: str) -> None:
        self.failed.append(f"{name}: {detail}")
        print(f"  {RED}FAIL{RESET}  {name}  ({detail})", file=sys.stderr)

    def check(self, name: str, condition: bool, detail: str = "") -> bool:
        if condition:
            self.ok(name, detail)
        else:
            self.fail(name, detail or "condition not met")
        return condition


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cloud-url", required=True,
                        help="base URL of the cloud read API, e.g. http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="seconds to wait for the deploy to come up (default: 120)")
    parser.add_argument("--expect-readings", type=int, default=1,
                        help="minimum stored readings before the run counts as healthy")
    parser.add_argument("--expect-pqc", action="store_true", default=True,
                        help="require hop 2 to have negotiated the hybrid PQC suite")
    parser.add_argument("--allow-classical", dest="expect_pqc", action="store_false",
                        help="permit a classical hop 2 (use only when testing that path)")
    args = parser.parse_args()

    base = args.cloud_url.rstrip("/")
    checks = Checks()

    print(f"{BOLD}smoke test against {base}{RESET}")

    # --- 1. liveness -------------------------------------------------------
    # Catches: container crash-looping, wrong port, image failed to start.
    print("\n[1/4] health")
    try:
        health = wait_for(f"{base}/health", timeout=args.timeout)
    except SmokeFailure as exc:
        checks.fail("cloud /health", str(exc))
        return report(checks)

    checks.check("cloud /health returns ok", health.get("status") == "ok",
                 f"status={health.get('status')}")
    checks.check("cloud advertises the hybrid suite",
                 "hybrid-x25519-mlkem768" in health.get("suites", []),
                 f"suites={health.get('suites')}")
    checks.check("cloud advertises both protocol versions",
                 {"wx-legacy/1", "wx-hybrid/2"} <= set(health.get("protocols", [])),
                 f"protocols={health.get('protocols')}")

    # --- 2. data actually flowing -----------------------------------------
    # Catches: keys not mounted, gateway cannot resolve the cloud, device
    # cannot reach the gateway, PQC policy mismatch refusing every handshake.
    # This is the check that distinguishes "running" from "working".
    print(f"\n[2/4] end-to-end data flow (waiting for >= {args.expect_readings} reading(s))")
    deadline = time.monotonic() + args.timeout
    stats: dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            stats = get_json(f"{base}/stats")
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
            time.sleep(3.0)
            continue
        if stats.get("storage", {}).get("total", 0) >= args.expect_readings:
            break
        time.sleep(3.0)

    total = stats.get("storage", {}).get("total", 0)
    if not checks.check("readings reached the cloud", total >= args.expect_readings,
                        f"stored={total}, wanted>={args.expect_readings}"):
        print(f"\n{YELLOW}hint: a deploy that is up but stores nothing usually means the "
              f"keys secret is missing or the gateway cannot reach the cloud.{RESET}",
              file=sys.stderr)

    messages = stats.get("messages", {})
    checks.check("no messages were rejected", messages.get("rejected", 0) == 0,
                 f"rejected={messages.get('rejected')}")

    # --- 3. post-quantum actually negotiated -------------------------------
    # Catches the failure this whole project exists to prevent: a silent
    # downgrade to classical because of a policy or version mismatch.
    print("\n[3/4] post-quantum key establishment")
    pqc = stats.get("pqc", {})
    print(f"        policy={pqc.get('policy')} hybrid={pqc.get('handshakes_hybrid')} "
          f"classical={pqc.get('handshakes_classical')} "
          f"refused={pqc.get('handshakes_downgrade_refused')}")

    if args.expect_pqc:
        checks.check("hop 2 negotiated hybrid PQC",
                     (pqc.get("handshakes_hybrid") or 0) > 0,
                     f"handshakes_hybrid={pqc.get('handshakes_hybrid')}")
        checks.check("no classical fallback occurred",
                     pqc.get("handshakes_classical", 0) == 0,
                     f"handshakes_classical={pqc.get('handshakes_classical')}")
        checks.check("pqc_fraction is 1.0", pqc.get("pqc_fraction") == 1.0,
                     f"pqc_fraction={pqc.get('pqc_fraction')}")
    else:
        checks.ok("PQC assertions skipped (--allow-classical)")

    # --- 4. read API -------------------------------------------------------
    # Catches: storage wired up but unreadable, schema mismatch, empty rows.
    print("\n[4/4] read API")
    try:
        body = get_json(f"{base}/readings?limit=3")
        rows = body.get("readings", [])
        checks.check("read API returns rows", len(rows) > 0, f"count={body.get('count')}")
        if rows:
            row = rows[0]
            required = {"date", "temp_max_c", "temp_min_c", "precip_mm",
                        "wind_max_kmh", "device_id", "gateway_id"}
            missing = required - set(row)
            checks.check("reading rows are complete", not missing,
                         f"missing={sorted(missing)}" if missing else "all fields present")
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        checks.fail("read API", str(exc))

    return report(checks)


def report(checks: Checks) -> int:
    total = checks.passed + len(checks.failed)
    print()
    if checks.failed:
        print(f"{RED}{BOLD}SMOKE TEST FAILED{RESET}  "
              f"{checks.passed}/{total} checks passed", file=sys.stderr)
        for failure in checks.failed:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"{GREEN}{BOLD}SMOKE TEST PASSED{RESET}  {checks.passed}/{total} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
