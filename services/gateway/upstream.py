"""The gateway's link to the cloud.

Two implementations share one interface. The legacy one exists so that a
partially migrated fleet still works and so the baseline stays reproducible;
the hybrid one is the migration target. Which is used is a configuration
choice, not a code change, which is what makes the rollout reversible.
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx

import pqcsuite as cs
from pqcwire.frames import DataFrame, b64d
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
    """Post-quantum relay: ML-KEM-768 + X25519, with per-session ephemeral keys."""

    suite = HYBRID_PQC
    frames_path = "/pqc/frames"

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        super().__init__(base_url, timeout)
        self._identity: Any = None

    def _identity_key(self) -> Any:
        # The long-term identity is cached, but the offers it signs are not:
        # a fresh offer per session is what provides forward secrecy.
        if self._identity is None:
            payload = self._get("/pqc/identity").json()
            self._identity = cs.load_identity_public(b64d(payload["public_key"]))
        return self._identity

    def open_session(self) -> tuple[str, cs.RecordSession]:
        offer = cs.Offer.from_dict(self._get("/pqc/offer").json())
        client = cs.HybridClient(self._identity_key())
        try:
            request, session = client.open_session(offer)
        except cs.CapabilityError as exc:
            raise UpstreamError(f"this node cannot run {self.suite}: {exc}") from exc
        self._post("/pqc/session", request.to_dict())
        return request.session_id, session


def build_upstream(base_url: str, mode: str, timeout: float = 5.0) -> Upstream:
    """Select the upstream suite.

    ``auto`` asks the cloud what it accepts and prefers the post-quantum suite
    when both ends support it. Falling back silently would be the wrong
    behaviour for a security control, so the caller logs the outcome.
    """
    mode = mode.strip().lower()
    if mode == "legacy":
        return LegacyUpstream(base_url, timeout)
    if mode == "hybrid":
        return HybridUpstream(base_url, timeout)
    if mode != "auto":
        raise UpstreamError(f"unknown upstream mode {mode!r}; expected hybrid, legacy, or auto")

    if HYBRID_PQC not in cs.supported_suites():
        return LegacyUpstream(base_url, timeout)
    try:
        accepted = httpx.get(f"{base_url.rstrip('/')}/capabilities", timeout=timeout).json()
    except (httpx.HTTPError, ValueError):
        # An unreachable peer says nothing about its capabilities, so assume
        # the safer suite rather than downgrading on a transient failure.
        return HybridUpstream(base_url, timeout)
    if HYBRID_PQC in accepted.get("accepted_suites", []):
        return HybridUpstream(base_url, timeout)
    return LegacyUpstream(base_url, timeout)
