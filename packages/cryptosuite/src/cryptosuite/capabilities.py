"""Runtime detection of which cipher suites this node can actually run.

The legacy device installs this same package against a pre-quantum build of
``cryptography``. ML-KEM is therefore absent at import time, and the hybrid
suite reports itself unavailable rather than failing somewhere deep in a
handshake. That makes the device's limitation a first-class, queryable
property instead of a crash.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Any

import cryptography

from wire.protocol import LEGACY_RSA

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem

    MLKEM_AVAILABLE = True
    _UNAVAILABLE_REASON: str | None = None
except ImportError as exc:  # pragma: no cover - depends on the installed build
    _mlkem = None  # type: ignore[assignment]
    MLKEM_AVAILABLE = False
    _UNAVAILABLE_REASON = (
        f"cryptography {cryptography.__version__} has no ML-KEM support ({exc}); "
        "ML-KEM requires cryptography>=48"
    )


class CapabilityError(RuntimeError):
    """Raised when a node is asked to perform an operation it cannot support."""


def mlkem_module() -> Any:
    if not MLKEM_AVAILABLE:
        raise CapabilityError(_UNAVAILABLE_REASON or "ML-KEM is unavailable on this node")
    return _mlkem


def supported_suites() -> list[str]:
    """Suites this node can actually run.

    Distinct from :data:`MLKEM_AVAILABLE`, which only reports what the crypto
    backend offers. At this baseline no post-quantum suite is implemented, so
    a capable backend still buys nothing.
    """
    return [LEGACY_RSA]


@dataclass(frozen=True)
class CapabilityReport:
    python_version: str
    cryptography_version: str
    mlkem_available: bool
    supported_suites: list[str]
    reason: str | None

    def to_dict(self) -> dict:
        return {
            "python_version": self.python_version,
            "cryptography_version": self.cryptography_version,
            "mlkem_available": self.mlkem_available,
            "supported_suites": list(self.supported_suites),
            "reason": self.reason,
        }


def probe() -> CapabilityReport:
    return CapabilityReport(
        python_version=platform.python_version(),
        cryptography_version=cryptography.__version__,
        mlkem_available=MLKEM_AVAILABLE,
        supported_suites=supported_suites(),
        reason=_UNAVAILABLE_REASON,
    )
