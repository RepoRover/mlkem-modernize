"""Protocol constants and the cipher-suite registry.

The suite identifier travels in every frame. It is what makes the migration
observable: an operator can count how much of the fleet is still speaking a
quantum-vulnerable suite, and the cloud can refuse those frames by policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

PROTOCOL_VERSION = 1

LEGACY_RSA = "LEGACY-RSA2048-OAEP-AESGCM"
HYBRID_PQC = "MLKEM768-X25519-HKDF-AESGCM"


@dataclass(frozen=True)
class SuiteSpec:
    suite_id: str
    quantum_resistant: bool
    kem: str
    kdf: str
    aead: str
    summary: str


SUITES: Dict[str, SuiteSpec] = {
    LEGACY_RSA: SuiteSpec(
        suite_id=LEGACY_RSA,
        quantum_resistant=False,
        kem="RSA-2048-OAEP-SHA256",
        kdf="none (raw shared secret used as key)",
        aead="AES-256-GCM",
        summary=(
            "Baseline mechanism. Vulnerable to harvest-now-decrypt-later: recovering the "
            "long-term RSA key retroactively decrypts every archived session."
        ),
    ),
    HYBRID_PQC: SuiteSpec(
        suite_id=HYBRID_PQC,
        quantum_resistant=True,
        kem="ML-KEM-768 + X25519 (hybrid)",
        kdf="HKDF-SHA256 with transcript binding",
        aead="AES-256-GCM",
        summary=(
            "Modernized mechanism. Hybrid construction stays secure if either the "
            "lattice or the elliptic-curve component is broken."
        ),
    ),
}


def suite_spec(suite_id: str) -> SuiteSpec:
    try:
        return SUITES[suite_id]
    except KeyError:
        raise UnknownSuiteError(suite_id) from None


class UnknownSuiteError(ValueError):
    def __init__(self, suite_id: str) -> None:
        super().__init__("unknown cipher suite: {!r}".format(suite_id))
        self.suite_id = suite_id
