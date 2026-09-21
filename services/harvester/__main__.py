"""Offline harvest-now-decrypt-later demonstration.

Usage:
    python -m services.harvester --capture run/capture/edge.jsonl \
        --rsa-key run/gateway/gateway_rsa.pem
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cryptosuite.legacy import load_private_key
from services.harvester.attack import LinkReport, harvest, load_capture

BANNER = """
================================================================================
  HARVEST-NOW-DECRYPT-LATER REPORT
================================================================================
  The attacker is handed the RSA private keys below. That models the end state
  of running Shor's algorithm against the captured public keys on a
  cryptographically relevant quantum computer -- no factoring is performed
  here. Traffic was recorded passively; nothing was modified in transit.
""".rstrip()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="harvester", description=__doc__)
    parser.add_argument(
        "--capture",
        action="append",
        required=True,
        type=Path,
        help="capture file written by the tap (repeatable)",
    )
    parser.add_argument(
        "--rsa-key",
        action="append",
        default=[],
        type=Path,
        help="recovered RSA private key in PEM form (repeatable)",
    )
    parser.add_argument("--json", type=Path, help="also write the report as JSON")
    return parser.parse_args(argv)


def render(reports: list[LinkReport], key_paths: list[Path]) -> str:
    lines = [BANNER, ""]
    lines.append("  keys held by attacker:")
    if key_paths:
        lines.extend(f"    - {path}" for path in key_paths)
    else:
        lines.append("    - (none)")
    lines.append("")

    for report in reports:
        verdict = "COMPROMISED" if report.compromised else "RESISTED"
        lines.append("-" * 80)
        lines.append(f"  link: {report.link:<20} verdict: {verdict}")
        suites = ", ".join(sorted(report.suites)) or "none"
        lines.append(f"  suites observed: {suites}")
        lines.append(
            f"  handshakes: {report.handshakes_seen}"
            f"   sessions recovered: {report.sessions_recovered}"
        )
        lines.append(
            f"  frames captured: {report.frames_seen}"
            f"   decrypted: {report.frames_decrypted} ({report.decryption_rate:.1%})"
        )
        for note in report.notes:
            lines.append(f"  note: {note}")
        if report.samples:
            lines.append("  recovered plaintext:")
            lines.extend(f"    {sample[:96]}" for sample in report.samples)
        lines.append("")

    compromised = [report.link for report in reports if report.compromised]
    lines.append("=" * 80)
    if compromised:
        lines.append(
            "  RESULT: {} link(s) fully readable: {}".format(
                len(compromised), ", ".join(compromised)
            )
        )
    else:
        lines.append("  RESULT: no captured traffic could be decrypted.")
    lines.append("=" * 80)
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    entries: list[dict[str, Any]] = []
    for path in args.capture:
        if not path.exists():
            print(f"capture file not found: {path}", file=sys.stderr)
            return 2
        entries.extend(load_capture(path))

    if not entries:
        print("no captured traffic found", file=sys.stderr)
        return 1

    keys = [load_private_key(path.read_bytes()) for path in args.rsa_key]
    reports = harvest(entries, keys)
    print(render(reports, args.rsa_key))

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps([report.to_dict() for report in reports], indent=2) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
