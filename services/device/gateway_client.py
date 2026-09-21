"""Hop 1 client: the legacy device's side of the device -> gateway channel.

Static-static ECDH P-256. No ephemeral keys, no signatures, and the ServerHello
is accepted without authentication. This models non-upgradeable firmware and is
NOT a template for anything new.

Treat this file as frozen: the premise of the project is that the device cannot
be changed, so the PQC migration must happen at the gateway and above.
"""

from __future__ import annotations

import binascii
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ..common import cryptoutil as cu
from ..common.handshake import HandshakeError, hop1_derive
from ..common.wire import HOP_DEVICE_GATEWAY, PROTOCOL, b64d, b64e


class GatewayClient:
    def __init__(
        self,
        base_url: str,
        device_id: str,
        device_static_key: cu.ec.EllipticCurvePrivateKey,
        gateway_public_key: cu.ec.EllipticCurvePublicKey,
        log: logging.Logger,
        timeout: float = 10.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._device_id = device_id
        self._device_static_key = device_static_key
        # Pinned at "manufacture". If the gateway's key ever changes, this
        # device is bricked -- no rotation path exists. Known weakness.
        self._gateway_public_key = gateway_public_key
        self._log = log
        # http_client is injected by the end-to-end test so it can talk to the
        # gateway app in-process instead of over a socket.
        self._client = http_client or httpx.Client(timeout=timeout)

        self._sender: cu.AeadSender | None = None
        self._session_id: bytes | None = None
        self._expires_at: datetime | None = None
        self._max_records: int = 0
        self._sent: int = 0

    def close(self) -> None:
        self._client.close()

    def _needs_handshake(self) -> bool:
        if self._sender is None or self._expires_at is None:
            return True
        if self._sent >= self._max_records:
            return True
        return datetime.now(timezone.utc) >= self._expires_at

    def handshake(self) -> None:
        client_nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        hello = {
            "protocol": PROTOCOL,
            "hop": HOP_DEVICE_GATEWAY,
            "client_id": self._device_id,
            "client_nonce": b64e(client_nonce),
        }

        response = self._client.post(f"{self._base_url}/handshake", json=hello)
        if response.status_code != 200:
            raise HandshakeError(f"gateway rejected ClientHello: HTTP {response.status_code}")

        try:
            body = response.json()
            session_id = b64d(body["session_id"])
            server_nonce = b64d(body["server_nonce"])
            nonce_prefix = b64d(body["nonce_prefix"])
            expires_at = body["expires_at"]
            max_records = int(body["max_records"])
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise HandshakeError(f"malformed ServerHello: {type(exc).__name__}") from exc

        # NOTE: nothing here authenticates the ServerHello. The gateway is
        # authenticated only implicitly -- if it is not the real gateway, the
        # derived key is wrong and every message we send is rejected with a tag
        # failure. We find out late and we cannot tell that case apart from
        # corruption. Deliberate hop 1 weakness.
        derived = hop1_derive(
            own_static_private=self._device_static_key,
            peer_static_public=self._gateway_public_key,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            session_id=session_id,
            nonce_prefix=nonce_prefix,
        )

        self._sender = cu.AeadSender(derived.key, session_id, nonce_prefix)
        self._session_id = session_id
        self._expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        self._max_records = max_records
        self._sent = 0

        self._log.info(
            "hop1 session established session=%s expires=%s",
            session_id.hex()[:12], expires_at,
        )

    def send_reading(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._needs_handshake():
            self.handshake()

        result = self._send_once(payload)
        if result.get("reason") == "session_expired":
            self._log.info("hop1 session gone, re-handshaking")
            self.handshake()
            result = self._send_once(payload)
        return result

    def _send_once(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._sender is None or self._session_id is None:
            # Not an assert: asserts are stripped under `python -O`, and this
            # invariant is what stops us encrypting with a half-built session.
            raise HandshakeError("no established session; call handshake() first")
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        seq, nonce, ciphertext = self._sender.encrypt(plaintext)
        self._sent += 1

        response = self._client.post(
            f"{self._base_url}/ingest",
            json={
                "session_id": b64e(self._session_id),
                "seq": seq,
                "nonce": b64e(nonce),
                "ct": b64e(ciphertext),
            },
        )
        try:
            return response.json()
        except ValueError:
            return {"status": "rejected", "reason": f"http_{response.status_code}"}
