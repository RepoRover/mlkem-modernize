"""Assert that a harvester report matches what a deployment should allow.

Used by scripts/verify_migration.sh and by CI. The modern case is the
regression that matters: if the backbone link ever becomes readable again, the
post-quantum integration has silently broken and the build should fail.
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in {"baseline", "modern"}:
        print("usage: check_attack_report.py [baseline|modern]  (report on stdin)", file=sys.stderr)
        return 2

    mode = argv[1]
    expected = {"edge": True, "backbone": mode == "baseline"}

    try:
        reports = {item["link"]: item for item in json.loads(sys.stdin.read())}
    except (ValueError, KeyError, TypeError) as exc:
        print(f"could not parse the attack report: {exc}", file=sys.stderr)
        return 2

    failures = []
    for link, should_be_readable in expected.items():
        report = reports.get(link)
        if report is None:
            failures.append(f"{link}: no traffic was captured on this link")
            continue

        readable = report["compromised"]
        verdict = "COMPROMISED" if readable else "RESISTED"
        suites = ", ".join(report["suites"]) or "none"
        print(
            f"  {link:<9} {verdict:<12} "
            f"{report['frames_decrypted']}/{report['frames_seen']} frames  [{suites}]"
        )
        if readable != should_be_readable:
            wanted = "readable" if should_be_readable else "unreadable"
            failures.append(f"{link}: expected {wanted}, got {verdict}")

    if failures:
        print("\nFAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"\nOK: every link behaved as the {mode} deployment requires")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
