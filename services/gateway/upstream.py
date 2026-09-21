"""The gateway's link to the cloud.

Two implementations share one interface. The legacy one exists so that a
partially migrated fleet still works and so the baseline stays reproducible;
the hybrid one is the migration target. Which is used is a configuration
choice, not a code change, which is what makes the rollout reversible.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

import httpx

import pqcsuite as cs
from pqcwire.frames import DataFrame
from pqcwire.protocol import HYBRID_PQC, LEGACY_RSA


class UpstreamError(RuntimeError):
    """Raised when the cloud is unreachable or rejects a request."""


class Upstream(Protocol):
    suite: str

    def open_session(self) -> tuple[str, cs.RecordSession]: ...

    def send(self, frame: DataFrame) -> None: ...

    def close(self) -> None: ...


class _HttpUpstream:
    frames_path = "/frames"

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    def _get(self, path: str) -> httpx.Response:
        try:
            response = self._client.get(self._base_url + path)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise UpstreamError(f"GET {path} failed: {exc}") from exc
        return response

    def _post(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        try:
            response = self._client.post(self._base_url + path, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise UpstreamError(f"POST {path} failed: {exc}") from exc
        return response

    def send(self, frame: DataFrame) -> None:
        self._post(self.frames_path, frame.to_dict())

    def close(self) -> None:
        self._client.close()


class LegacyUpstream(_HttpUpstream):
    """Quantum-vulnerable relay, retained for fallback and for the baseline."""

    suite = LEGACY_RSA
    frames_path = "/legacy/frames"

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        super().__init__(base_url, timeout)
        self._peer_public_key: Any = None

    def _public_key(self) -> Any:
        # Fetched lazily and cached: the cloud may still be starting when the
        # gateway comes up, and a startup fetch would make boot order matter.
        if self._peer_public_key is None:
            self._peer_public_key = cs.load_public_key(self._get("/legacy/pubkey").content)
        return self._peer_public_key

    def open_session(self) -> tuple[str, cs.RecordSession]:
        client = cs.LegacyClient(self._public_key())
        request, session = client.open_session()
        self._post("/legacy/session", request.to_dict())
        return request.session_id, session


class HybridUpstream(_HttpUpstream):
    """Post-quantum relay authenticated by an out-of-band identity pin."""

    suite = HYBRID_PQC
    frames_path = "/pqc/frames"

    def __init__(self, base_url: str, peer_identity: Any, timeout: float = 5.0) -> None:
        super().__init__(base_url, timeout)
        self._peer_identity = peer_identity

    def open_session(self) -> tuple[str, cs.RecordSession]:
        try:
            offer = cs.Offer.from_dict(self._get("/pqc/offer").json())
            client = cs.HybridClient(self._peer_identity)
            request, session = client.open_session(offer)
        except cs.CapabilityError as exc:
            raise UpstreamError(f"this node cannot run {self.suite}: {exc}") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise UpstreamError(f"cloud returned an invalid {self.suite} offer: {exc}") from exc
        self._post("/pqc/session", request.to_dict())
        return request.session_id, session


def _load_pinned_identity(path: Path | None) -> Any:
    if path is None:
        raise UpstreamError(
            "CLOUD_IDENTITY_PUBLIC_KEY_PATH is required for hybrid upstream authentication"
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UpstreamError(f"cannot read pinned cloud identity key {path}: {exc}") from exc
    try:
        return cs.load_identity_public(raw)
    except (TypeError, ValueError) as exc:
        raise UpstreamError(f"pinned cloud identity key {path} is malformed: {exc}") from exc


def build_upstream(
    base_url: str,
    mode: str,
    timeout: float = 5.0,
    identity_path: Path | None = None,
) -> Upstream:
    """Select the upstream suite without network-controlled downgrade.

    ``auto`` is retained as a compatibility alias for ``hybrid``. Selecting the
    legacy suite always requires explicit local configuration.
    """
    mode = mode.strip().lower()
    if mode == "legacy":
        return LegacyUpstream(base_url, timeout)
    if mode not in {"hybrid", "auto"}:
        raise UpstreamError(f"unknown upstream mode {mode!r}; expected hybrid, legacy, or auto")

    # Load and parse the trust anchor before any network request. Neither
    # hybrid nor its `auto` alias can silently downgrade to legacy.
    peer_identity = _load_pinned_identity(identity_path)
    if HYBRID_PQC not in cs.supported_suites():
        raise UpstreamError(
            f"this node cannot run {HYBRID_PQC}; set UPSTREAM_SUITE=legacy explicitly to fall back"
        )
    return HybridUpstream(base_url, peer_identity, timeout)
