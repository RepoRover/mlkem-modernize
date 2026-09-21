"""Strictly validate attack evidence and matching cloud storage evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

LEGACY_RSA = "LEGACY-RSA2048-OAEP-AESGCM"
HYBRID_PQC = "MLKEM768-X25519-HKDF-AESGCM"


def validate(mode: str, raw_reports: Any, cloud: Any) -> list[str]:
    """Return every evidence failure instead of stopping at the first one."""
    failures: list[str] = []
    if mode not in {"baseline", "modern"}:
        return [f"unknown mode {mode!r}"]
    if not isinstance(raw_reports, list):
        return ["attack report must be a JSON list"]
    if not isinstance(cloud, dict):
        return ["cloud report must be a JSON object"]

    reports: dict[str, dict[str, Any]] = {}
    for item in raw_reports:
        if not isinstance(item, dict) or not isinstance(item.get("link"), str):
            failures.append("attack report contains an invalid link entry")
            continue
        reports[item["link"]] = item

    expected_suites = {
        "edge": LEGACY_RSA,
        "backbone": LEGACY_RSA if mode == "baseline" else HYBRID_PQC,
    }
    for link, expected_suite in expected_suites.items():
        report = reports.get(link)
        if report is None:
            failures.append(f"{link}: no traffic was captured on this link")
            continue
        try:
            seen = int(report["frames_seen"])
            decrypted = int(report["frames_decrypted"])
            suites = report["suites"]
        except (KeyError, TypeError, ValueError):
            failures.append(f"{link}: malformed frame evidence")
            continue
        if seen <= 0:
            failures.append(f"{link}: expected nonzero captured frames")
        if not isinstance(suites, list) or suites != [expected_suite]:
            failures.append(f"{link}: expected only suite {expected_suite}, got {suites!r}")

        readable = link == "edge" or mode == "baseline"
        expected_decrypted = seen if readable else 0
        verdict = "COMPROMISED" if decrypted else "RESISTED"
        shown_suites = ", ".join(suites) if isinstance(suites, list) else "invalid"
        print(f"  {link:<9} {verdict:<12} {decrypted}/{seen} frames  [{shown_suites}]")
        if decrypted != expected_decrypted:
            failures.append(
                f"{link}: expected {expected_decrypted}/{seen} decrypted frames, got {decrypted}"
            )

    expected_cloud_suite = expected_suites["backbone"]
    total = cloud.get("total")
    by_suite = cloud.get("by_suite")
    if not isinstance(total, int) or total <= 0:
        failures.append("cloud: expected at least one stored reading")
    if not isinstance(by_suite, dict) or not isinstance(by_suite.get(expected_cloud_suite), int):
        failures.append(f"cloud: no count for expected suite {expected_cloud_suite}")
    elif by_suite[expected_cloud_suite] <= 0:
        failures.append(f"cloud: expected stored readings under {expected_cloud_suite}")

    return failures


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] not in {"baseline", "modern"}:
        print(
            "usage: check_attack_report.py [baseline|modern] ATTACK_JSON CLOUD_JSON",
            file=sys.stderr,
        )
        return 2

    try:
        raw_reports = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        cloud = json.loads(Path(argv[3]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"could not parse migration evidence: {exc}", file=sys.stderr)
        return 2

    failures = validate(argv[1], raw_reports, cloud)
    if failures:
        print("\nFAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"\nOK: every link and cloud storage behaved as the {argv[1]} deployment requires")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
