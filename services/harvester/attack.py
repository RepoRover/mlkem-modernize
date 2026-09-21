"""Offline analysis of captured traffic.

What this does and does not simulate, stated plainly: the attacker is *handed*
the RSA private key. That is the end state of running Shor's algorithm against
the captured public key on a cryptographically relevant quantum computer. No
factoring happens here. The demonstration is of the consequence -- that one
recovered long-term key retroactively unlocks every archived session -- not of
the method.

Nothing in this module respects the protocol's replay or ordering rules. An
attacker holding a session key decrypts whatever it captured, in any order,
which is precisely why those rules protect integrity rather than secrecy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptosuite.legacy import recover_session_key
from wire.frames import DataFrame, FrameError, HandshakeRequest
from wire.protocol import HYBRID_PQC, LEGACY_RSA

HANDSHAKE_PATHS = {"/legacy/session", "/pqc/session"}
FRAME_PATHS = {"/legacy/frames", "/pqc/frames"}


@dataclass
class LinkReport:
    link: str
    suites: set[str] = field(default_factory=set)
    handshakes_seen: int = 0
    sessions_recovered: int = 0
    frames_seen: int = 0
    frames_decrypted: int = 0
    samples: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def compromised(self) -> bool:
        return self.frames_decrypted > 0

    @property
    def decryption_rate(self) -> float:
        return self.frames_decrypted / self.frames_seen if self.frames_seen else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "link": self.link,
            "suites": sorted(self.suites),
            "handshakes_seen": self.handshakes_seen,
            "sessions_recovered": self.sessions_recovered,
            "frames_seen": self.frames_seen,
            "frames_decrypted": self.frames_decrypted,
            "decryption_rate": round(self.decryption_rate, 4),
            "compromised": self.compromised,
            "samples": self.samples,
            "notes": self.notes,
        }


def load_capture(path: Path) -> list[dict[str, Any]]:
    entries = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    return entries


def decrypt_captured_frame(key: bytes, frame: DataFrame) -> bytes:
    """Decrypt one captured frame with a recovered session key."""
    return AESGCM(key).decrypt(frame.nonce(), frame.ciphertext, frame.aad())


def harvest(entries: list[dict[str, Any]], rsa_keys: list[Any]) -> list[LinkReport]:
    reports: dict[str, LinkReport] = {}
    session_keys: dict[str, bytes] = {}

    for entry in entries:
        link = str(entry.get("link", "unknown"))
        report = reports.setdefault(link, LinkReport(link=link))
        body = entry.get("request_json")
        if not isinstance(body, dict):
            continue
        path = str(entry.get("path", ""))

        if path in HANDSHAKE_PATHS:
            _attempt_handshake(report, body, rsa_keys, session_keys)
        elif path in FRAME_PATHS:
            _attempt_frame(report, body, session_keys)

    for report in reports.values():
        _annotate(report)
    return sorted(reports.values(), key=lambda item: item.link)


def _attempt_handshake(
    report: LinkReport,
    body: dict[str, Any],
    rsa_keys: list[Any],
    session_keys: dict[str, bytes],
) -> None:
    try:
        request = HandshakeRequest.from_dict(body)
    except FrameError:
        return

    report.handshakes_seen += 1
    report.suites.add(request.suite)

    if request.suite != LEGACY_RSA:
        # ML-KEM ciphertexts yield nothing to an attacker holding classical
        # private keys, and the responder's KEM key was ephemeral anyway.
        return

    # Try every key the attacker holds: a capture may span links protected by
    # different long-term keys, and only one of them will match.
    for key in rsa_keys:
        try:
            session_keys[request.session_id] = recover_session_key(key, request)
        except (ValueError, KeyError, FrameError):
            continue
        report.sessions_recovered += 1
        return


def _attempt_frame(
    report: LinkReport, body: dict[str, Any], session_keys: dict[str, bytes]
) -> None:
    try:
        frame = DataFrame.from_dict(body)
    except FrameError:
        return

    report.frames_seen += 1
    report.suites.add(frame.suite)

    key = session_keys.get(frame.session_id)
    if key is None:
        return

    try:
        plaintext = decrypt_captured_frame(key, frame)
    except (InvalidTag, FrameError):
        return

    report.frames_decrypted += 1
    if len(report.samples) < 3:
        report.samples.append(plaintext.decode("utf-8", errors="replace"))


def _annotate(report: LinkReport) -> None:
    if HYBRID_PQC in report.suites and report.frames_decrypted == 0:
        report.notes.append(
            "ML-KEM ciphertexts carry no classically recoverable secret, and the "
            "responder's KEM keys were ephemeral and discarded after use."
        )
    if LEGACY_RSA in report.suites and report.frames_decrypted:
        report.notes.append(
            "One recovered long-term RSA key unlocked every archived session on "
            "this link. This is the harvest-now-decrypt-later exposure."
        )
    if LEGACY_RSA in report.suites and not report.sessions_recovered:
        report.notes.append(
            "Legacy traffic was observed but no matching RSA private key was "
            "supplied, so the session keys stayed out of reach."
        )
