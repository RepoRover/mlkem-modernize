"""The gateway's bounded, authenticated link to the cloud.

Legacy remains available only through explicit local configuration so the
baseline stays reproducible. Hybrid is the default and mutually authenticates
pinned ML-DSA identities while retaining ephemeral ML-KEM + X25519 key exchange.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

import pqcsuite as cs
from pqcwire.frames import DataFrame
from pqcwire.protocol import HYBRID_PQC, LEGACY_RSA

DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024


class UpstreamError(RuntimeError):
    """Raised when the cloud is unreachable, unsafe, or rejects a request."""


class UpstreamSessionRejected(UpstreamError):
    """Raised when the cloud requires a fresh single-use session."""


class Upstream(Protocol):
    suite: str

    def open_session(self) -> tuple[str, cs.RecordSession]: ...

    def send(self, frame: DataFrame) -> None: ...

    def ready(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class UpstreamPolicy:
    timeout_seconds: float = 5.0
    deadline_seconds: float = 12.0
    retry_attempts: int = 3
    retry_initial_seconds: float = 0.1
    retry_max_seconds: float = 1.0
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        timings = (
            self.timeout_seconds,
            self.deadline_seconds,
            self.retry_initial_seconds,
            self.retry_max_seconds,
        )
        if not all(math.isfinite(value) for value in timings):
            raise UpstreamError("upstream timeout and retry settings must be finite")
        if self.timeout_seconds <= 0 or self.deadline_seconds <= 0:
            raise UpstreamError("upstream timeout and deadline must be positive")
        if not 1 <= self.retry_attempts <= 10:
            raise UpstreamError("UPSTREAM_RETRY_ATTEMPTS must be between 1 and 10")
        if self.retry_initial_seconds < 0 or self.retry_max_seconds < 0:
            raise UpstreamError("upstream retry delays must not be negative")
        if self.retry_initial_seconds > self.retry_max_seconds:
            raise UpstreamError("upstream initial retry delay must not exceed its maximum")
        if self.max_response_bytes < 1:
            raise UpstreamError("UPSTREAM_MAX_RESPONSE_BYTES must be positive")


class _HttpUpstream:
    frames_path = "/frames"

    def __init__(self, base_url: str, policy: UpstreamPolicy) -> None:
        self._base_url = base_url.rstrip("/")
        self._policy = policy
        self._client = httpx.Client(timeout=policy.timeout_seconds)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        retryable: bool,
    ) -> httpx.Response:
        attempts = self._policy.retry_attempts if retryable else 1
        deadline = time.monotonic() + self._policy.deadline_seconds
        last_error = "upstream request failed"

        for attempt in range(1, attempts + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            timeout = min(self._policy.timeout_seconds, remaining)
            attempt_deadline = time.monotonic() + timeout
            try:
                with self._client.stream(
                    method,
                    self._base_url + path,
                    json=payload,
                    headers={"Accept-Encoding": "identity"},
                    timeout=timeout,
                ) as streamed:
                    encoding = streamed.headers.get("content-encoding", "identity").lower()
                    if encoding != "identity":
                        raise UpstreamError(
                            f"{method} {path} returned unsupported compressed content"
                        )
                    declared = streamed.headers.get("content-length")
                    if declared is not None and int(declared) > self._policy.max_response_bytes:
                        raise UpstreamError(f"{method} {path} response is too large")
                    body = bytearray()
                    for chunk in streamed.iter_bytes():
                        if time.monotonic() >= attempt_deadline:
                            raise httpx.ReadTimeout(
                                f"{method} {path} exceeded its per-attempt timeout",
                                request=streamed.request,
                            )
                        if len(body) + len(chunk) > self._policy.max_response_bytes:
                            raise UpstreamError(f"{method} {path} response is too large")
                        body.extend(chunk)
                    if time.monotonic() >= attempt_deadline:
                        raise httpx.ReadTimeout(
                            f"{method} {path} exceeded its per-attempt timeout",
                            request=streamed.request,
                        )
                    response = httpx.Response(
                        streamed.status_code,
                        headers=streamed.headers,
                        content=bytes(body),
                        request=httpx.Request(method, self._base_url + path),
                    )
            except (httpx.HTTPError, ValueError) as exc:
                last_error = str(exc)
            else:
                if response.status_code < 400:
                    return response
                if response.status_code == 409:
                    raise UpstreamSessionRejected(f"{method} {path} returned HTTP 409")
                last_error = f"HTTP {response.status_code}"
                if response.status_code not in {408, 429} and response.status_code < 500:
                    break

            if attempt < attempts:
                delay = min(
                    self._policy.retry_max_seconds,
                    self._policy.retry_initial_seconds * (2 ** (attempt - 1)),
                )
                remaining = deadline - time.monotonic()
                if delay >= remaining:
                    break
                time.sleep(delay)

        raise UpstreamError(f"{method} {path} failed within bounded attempts: {last_error}")

    def _get(self, path: str) -> httpx.Response:
        return self._request("GET", path, retryable=True)

    def _post(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        # Handshake and frame POSTs are deliberately not retried: their server
        # state is single-use, so an ambiguous response cannot be replayed safely.
        return self._request("POST", path, payload, retryable=False)

    def send(self, frame: DataFrame) -> None:
        self._post(self.frames_path, frame.to_dict())

    def ready(self) -> None:
        self._get("/readyz")

    def close(self) -> None:
        self._client.close()


class LegacyUpstream(_HttpUpstream):
    """Quantum-vulnerable relay, retained for explicit rollback and baseline."""

    suite = LEGACY_RSA
    frames_path = "/legacy/frames"

    def __init__(self, base_url: str, policy: UpstreamPolicy) -> None:
        super().__init__(base_url, policy)
        self._peer_public_key: Any = None

    def _public_key(self) -> Any:
        if self._peer_public_key is None:
            self._peer_public_key = cs.load_public_key(self._get("/legacy/pubkey").content)
        return self._peer_public_key

    def open_session(self) -> tuple[str, cs.RecordSession]:
        client = cs.LegacyClient(self._public_key())
        request, session = client.open_session()
        self._post("/legacy/session", request.to_dict())
        return request.session_id, session


class HybridUpstream(_HttpUpstream):
    """Hybrid relay with pinned, mutual ML-DSA authentication."""

    suite = HYBRID_PQC
    frames_path = "/pqc/frames"

    def __init__(
        self,
        base_url: str,
        peer_identity: Any,
        identity_key: Any,
        policy: UpstreamPolicy,
    ) -> None:
        super().__init__(base_url, policy)
        self._peer_identity = peer_identity
        self._identity_key = identity_key

    def open_session(self) -> tuple[str, cs.RecordSession]:
        try:
            offer = cs.Offer.from_dict(self._get("/pqc/offer").json())
            client = cs.HybridClient(self._peer_identity, self._identity_key)
            request, session = client.open_session(offer)
        except cs.CapabilityError as exc:
            raise UpstreamError(f"this node cannot run {self.suite}: {exc}") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise UpstreamError(f"cloud returned an invalid {self.suite} offer: {exc}") from exc
        self._post("/pqc/session", request.to_dict())
        return request.session_id, session


def _read_identity(path: Path | None, *, private: bool, variable: str) -> Any:
    if path is None:
        raise UpstreamError(f"{variable} is required for hybrid upstream authentication")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UpstreamError(f"cannot read identity key {path}: {exc}") from exc
    try:
        return cs.load_identity_private(raw) if private else cs.load_identity_public(raw)
    except (TypeError, ValueError) as exc:
        raise UpstreamError(f"identity key {path} is malformed: {exc}") from exc


def build_upstream(
    base_url: str,
    mode: str,
    timeout: float = 5.0,
    identity_path: Path | None = None,
    gateway_identity_path: Path | None = None,
    *,
    deadline: float = 12.0,
    retry_attempts: int = 3,
    retry_initial: float = 0.1,
    retry_max: float = 1.0,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> Upstream:
    """Select the upstream suite without discovery or network downgrade."""
    policy = UpstreamPolicy(
        timeout_seconds=timeout,
        deadline_seconds=deadline,
        retry_attempts=retry_attempts,
        retry_initial_seconds=retry_initial,
        retry_max_seconds=retry_max,
        max_response_bytes=max_response_bytes,
    )
    mode = mode.strip().lower()
    if mode == "legacy":
        return LegacyUpstream(base_url, policy)
    if mode not in {"hybrid", "auto"}:
        raise UpstreamError(f"unknown upstream mode {mode!r}; expected hybrid, legacy, or auto")

    peer_identity = _read_identity(
        identity_path, private=False, variable="CLOUD_IDENTITY_PUBLIC_KEY_PATH"
    )
    identity_key = _read_identity(
        gateway_identity_path, private=True, variable="GATEWAY_IDENTITY_PATH"
    )
    if HYBRID_PQC not in cs.supported_suites():
        raise UpstreamError(
            f"this node cannot run {HYBRID_PQC}; set UPSTREAM_SUITE=legacy explicitly to fall back"
        )
    return HybridUpstream(base_url, peer_identity, identity_key, policy)
