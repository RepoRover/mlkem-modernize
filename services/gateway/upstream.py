"""Client for the gateway's link to the cloud.

At this baseline the upstream link uses the same legacy suite as the device
link, so traffic is quantum-vulnerable end to end. Isolating it behind this
class is what lets the migration replace one link without touching the other.
"""

from __future__ import annotations

import httpx

import cryptosuite as cs
from wire.frames import DataFrame
from wire.protocol import LEGACY_RSA


class UpstreamError(RuntimeError):
    """Raised when the cloud is unreachable or rejects a frame."""


class LegacyUpstream:
    """Opens legacy sessions to the cloud and relays frames over them."""

    suite = LEGACY_RSA

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)
        self._peer_public_key: object | None = None

    def _public_key(self) -> object:
        # Fetched lazily and cached: the cloud may still be starting when the
        # gateway comes up, and a startup fetch would make boot order matter.
        if self._peer_public_key is None:
            try:
                response = self._client.get(f"{self._base_url}/legacy/pubkey")
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise UpstreamError(f"cannot fetch cloud public key: {exc}") from exc
            self._peer_public_key = cs.load_public_key(response.content)
        return self._peer_public_key

    def open_session(self) -> tuple[str, cs.RecordSession]:
        client = cs.LegacyClient(self._public_key())  # type: ignore[arg-type]
        request, session = client.open_session()
        try:
            response = self._client.post(f"{self._base_url}/legacy/session", json=request.to_dict())
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise UpstreamError(f"cloud rejected the handshake: {exc}") from exc
        return request.session_id, session

    def send(self, frame: DataFrame) -> None:
        try:
            response = self._client.post(f"{self._base_url}/legacy/frames", json=frame.to_dict())
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise UpstreamError(f"cloud rejected the frame: {exc}") from exc

    def close(self) -> None:
        self._client.close()
