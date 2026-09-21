"""Hop 2 client: the gateway's side of the gateway -> cloud channel.

Ephemeral ECDH + mutual ECDSA. Re-handshakes when the session's record budget
or TTL runs out, or when the cloud tells us the session is gone.

This class is the migration target. Swapping in hybrid X25519 + ML-KEM-768 means
changing what goes into the ClientHello and which derive function is called;
the send/rekey logic above it does not move.
"""

from __future__ import annotations

import binascii
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ..common import cryptoutil as cu
from ..common.handshake import (
    HandshakeError,
    hop2_client_transcript,
    hop2_derive,
    hop2_server_transcript,
)
from ..common.wire import HOP_GATEWAY_CLOUD, PROTOCOL, b64d, b64e


class CloudClient:
    def __init__(
        self,
        base_url: str,
        gateway_id: str,
        signing_key: "cu.ec.EllipticCurvePrivateKey",
        cloud_public_key: "cu.ec.EllipticCurvePublicKey",
        log: logging.Logger,
        timeout: float = 10.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._gateway_id = gateway_id
        self._signing_key = signing_key
        self._cloud_public_key = cloud_public_key
        self._log = log
        # http_client is injected by the end-to-end test so it can talk to the
        # cloud app in-process instead of over a socket.
        self._client = http_client or httpx.Client(timeout=timeout)

        self._sender: cu.AeadSender | None = None
        self._session_id: bytes | None = None
        self._expires_at: datetime | None = None
        self._max_records: int = 0
        self._sent: int = 0

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------- handshake

    def _needs_handshake(self) -> bool:
        if self._sender is None or self._expires_at is None:
            return True
        if self._sent >= self._max_records:
            return True
        return datetime.now(timezone.utc) >= self._expires_at

    def handshake(self) -> None:
        client_nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        eph_priv = cu.generate_private_key()
        eph_pub_raw = cu.public_key_to_bytes(eph_priv.public_key())

        transcript = hop2_client_transcript(self._gateway_id, client_nonce, eph_pub_raw)
        hello = {
            "protocol": PROTOCOL,
            "hop": HOP_GATEWAY_CLOUD,
            "client_id": self._gateway_id,
            "client_nonce": b64e(client_nonce),
            "eph_pub": b64e(eph_pub_raw),
            "sig": b64e(cu.sign(self._signing_key, transcript)),
        }

        response = self._client.post(f"{self._base_url}/handshake", json=hello)
        if response.status_code != 200:
            raise HandshakeError(f"cloud rejected ClientHello: HTTP {response.status_code}")

        try:
            body = response.json()
            session_id = b64d(body["session_id"])
            server_nonce = b64d(body["server_nonce"])
            server_eph_pub_raw = b64d(body["eph_pub"])
            nonce_prefix = b64d(body["nonce_prefix"])
            expires_at = body["expires_at"]
            max_records = int(body["max_records"])
            signature = b64d(body["sig"])
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise HandshakeError(f"malformed ServerHello: {type(exc).__name__}") from exc

        # Explicit server authentication. Without this the cloud could be any
        # host that answered the connection, since we have no TLS underneath.
        server_transcript = hop2_server_transcript(
            client_id=self._gateway_id,
            client_nonce=client_nonce,
            client_eph_pub=eph_pub_raw,
            session_id=session_id,
            server_nonce=server_nonce,
            server_eph_pub=server_eph_pub_raw,
            nonce_prefix=nonce_prefix,
            expires_at=expires_at,
            max_records=max_records,
        )
        if not cu.verify(self._cloud_public_key, signature, server_transcript):
            raise HandshakeError("cloud ServerHello signature did not verify")

        try:
            server_eph_pub = cu.public_key_from_bytes(server_eph_pub_raw)
        except ValueError as exc:
            raise HandshakeError("cloud sent an invalid ephemeral public key") from exc

        derived = hop2_derive(
            own_ephemeral_private=eph_priv,
            peer_ephemeral_public=server_eph_pub,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            client_eph_pub=eph_pub_raw,
            server_eph_pub=server_eph_pub_raw,
            session_id=session_id,
            nonce_prefix=nonce_prefix,
        )

        self._sender = cu.AeadSender(derived.key, session_id, nonce_prefix)
        self._session_id = session_id
        self._expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        self._max_records = max_records
        self._sent = 0

        self._log.info(
            "hop2 session established session=%s expires=%s",
            session_id.hex()[:12],
            expires_at,
        )

    # ------------------------------------------------------------------ send

    def send(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Encrypt and forward one envelope, re-handshaking if needed."""
        if self._needs_handshake():
            self.handshake()

        result = self._send_once(envelope)
        if result.get("reason") == "session_expired":
            # The cloud restarted or pruned us; establish a new session and retry once.
            self._log.info("hop2 session gone, re-handshaking")
            self.handshake()
            result = self._send_once(envelope)
        return result

    def _send_once(self, envelope: dict[str, Any]) -> dict[str, Any]:
        assert self._sender is not None and self._session_id is not None
        plaintext = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
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
