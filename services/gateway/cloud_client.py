"""Hop 2 client: the gateway's side of the gateway -> cloud channel.

Offers `hybrid-x25519-mlkem768` and (unless policy forbids) `classical-p256`,
with a key share for each, so negotiation costs no extra round trip.

The gateway generates the ML-KEM-768 keypair and the cloud encapsulates to it.
The keypair is ephemeral -- fresh per handshake, discarded immediately after --
which is what gives the post-quantum half its forward secrecy.

Downgrade protection on this side:
  * we sign our whole offer, so it cannot be edited in flight;
  * we verify the cloud's signature over that same offer, so a ServerHello that
    answers a *different* offer is rejected;
  * under policy=require we refuse a classical selection outright, even one the
    cloud legitimately signed.
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
    KeyShare,
    hop2_v2_client_transcript,
    hop2_v2_derive,
    hop2_v2_server_transcript,
)
from ..common.suites import (
    SUITE_CLASSICAL,
    SUITE_HYBRID,
    Policy,
    canonical_suites,
    client_offer,
    is_post_quantum,
)
from ..common.wire import HOP_GATEWAY_CLOUD, PROTOCOL_V2, b64d, b64e


class DowngradeRejected(HandshakeError):
    """The cloud selected a classical suite but our policy requires PQC."""


class CloudClient:
    def __init__(
        self,
        base_url: str,
        gateway_id: str,
        signing_key: cu.ec.EllipticCurvePrivateKey,
        cloud_public_key: cu.ec.EllipticCurvePublicKey,
        log: logging.Logger,
        timeout: float = 10.0,
        http_client: httpx.Client | None = None,
        policy: Policy = Policy.PREFER,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._gateway_id = gateway_id
        self._signing_key = signing_key
        self._cloud_public_key = cloud_public_key
        self._log = log
        self._policy = policy
        # http_client is injected by tests so they can talk to the cloud app
        # in-process instead of over a socket.
        self._client = http_client or httpx.Client(timeout=timeout)

        self._sender: cu.AeadSender | None = None
        self._session_id: bytes | None = None
        self._expires_at: datetime | None = None
        self._max_records: int = 0
        self._sent: int = 0
        self._suite: str | None = None

        self.handshakes_hybrid = 0
        self.handshakes_classical = 0

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def suite(self) -> str | None:
        """Suite of the current session, or None before the first handshake."""
        return self._suite

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
        offered = client_offer(self._policy)

        # Build a key share for every suite we offer. Ephemeral, single-use.
        shares: dict[str, KeyShare] = {}
        x25519_priv = None
        mlkem_priv = None
        p256_priv = None

        if SUITE_HYBRID in offered:
            x25519_priv = cu.generate_x25519_private_key()
            mlkem_priv = cu.generate_mlkem768_private_key()
            shares[SUITE_HYBRID] = KeyShare(
                x25519_pub=cu.x25519_public_bytes(x25519_priv.public_key()),
                mlkem768_ek=cu.mlkem768_encapsulation_key_bytes(mlkem_priv),
            )
        if SUITE_CLASSICAL in offered:
            p256_priv = cu.generate_private_key()
            shares[SUITE_CLASSICAL] = KeyShare(
                p256_pub=cu.public_key_to_bytes(p256_priv.public_key())
            )

        client_nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        transcript = hop2_v2_client_transcript(
            client_id=self._gateway_id,
            client_nonce=client_nonce,
            offered_suites=offered,
            shares=shares,
        )

        hello: dict[str, Any] = {
            "protocol": PROTOCOL_V2,
            "hop": HOP_GATEWAY_CLOUD,
            "client_id": self._gateway_id,
            "client_nonce": b64e(client_nonce),
            "offered_suites": list(offered),
            "key_shares": {
                suite: _encode_share(suite, share) for suite, share in shares.items()
            },
            "sig": b64e(cu.sign(self._signing_key, transcript)),
        }

        response = self._client.post(f"{self._base_url}/handshake", json=hello)
        if response.status_code != 200:
            reason = _reason_of(response)
            if reason == "downgrade_refused":
                # The cloud requires PQC and we did not offer it. Actionable.
                raise HandshakeError(
                    "cloud refused a classical-only offer (policy=require on the cloud); "
                    f"gateway offered [{canonical_suites(list(offered))}]"
                )
            raise HandshakeError(
                f"cloud rejected ClientHello: HTTP {response.status_code} ({reason})"
            )

        try:
            body = response.json()
            if body.get("protocol") != PROTOCOL_V2:
                raise HandshakeError("cloud answered with an unexpected protocol version")
            selected = body["selected_suite"]
            session_id = b64d(body["session_id"])
            server_nonce = b64d(body["server_nonce"])
            nonce_prefix = b64d(body["nonce_prefix"])
            expires_at = body["expires_at"]
            max_records = int(body["max_records"])
            signature = b64d(body["sig"])

            if selected == SUITE_HYBRID:
                server_share = KeyShare(x25519_pub=b64d(body["x25519_pub"]))
                mlkem_ct = b64d(body["mlkem768_ct"])
            elif selected == SUITE_CLASSICAL:
                server_share = KeyShare(p256_pub=b64d(body["eph_pub"]))
                mlkem_ct = b""
            else:
                raise HandshakeError(f"cloud selected an unknown suite {selected!r}")
        except HandshakeError:
            raise
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise HandshakeError(f"malformed ServerHello: {type(exc).__name__}") from exc

        # The cloud may only pick something we actually offered.
        if selected not in offered:
            raise HandshakeError(f"cloud selected {selected!r}, which we did not offer")

        # Client-side downgrade enforcement. Even a correctly signed classical
        # ServerHello is refused when our policy requires PQC -- the signature
        # proves the cloud said it, not that it is acceptable to us.
        if self._policy is Policy.REQUIRE and not is_post_quantum(selected):
            raise DowngradeRejected(
                f"cloud selected {selected!r} but gateway policy is 'require'"
            )

        # Verify over the transcript WE sent. If anyone edited our offer in
        # flight, the cloud signed different bytes and this fails.
        server_transcript = hop2_v2_server_transcript(
            client_id=self._gateway_id,
            client_nonce=client_nonce,
            offered_suites=offered,
            client_shares=shares,
            selected_suite=selected,
            session_id=session_id,
            server_nonce=server_nonce,
            server_share=server_share,
            mlkem768_ct=mlkem_ct,
            nonce_prefix=nonce_prefix,
            expires_at=expires_at,
            max_records=max_records,
        )
        if not cu.verify(self._cloud_public_key, signature, server_transcript):
            raise HandshakeError(
                "cloud ServerHello signature did not verify "
                "(offer tampering or wrong cloud key)"
            )

        # --- key agreement ---------------------------------------------------
        client_share = shares[selected]
        ss_mlkem = b""
        try:
            if selected == SUITE_HYBRID:
                if x25519_priv is None or mlkem_priv is None:
                    raise HandshakeError("hybrid selected but no hybrid key share was built")
                ss_classical = cu.x25519_exchange(
                    x25519_priv, cu.x25519_public_from_bytes(server_share.x25519_pub)
                )
                # Implicit rejection: a tampered ciphertext does NOT raise here.
                # It yields a different pseudorandom secret, and the mismatch
                # surfaces as an AEAD tag failure on our first message.
                ss_mlkem = cu.mlkem768_decapsulate(mlkem_priv, mlkem_ct)
            else:
                if p256_priv is None:
                    raise HandshakeError("classical selected but no P-256 share was built")
                ss_classical = cu.ecdh(
                    p256_priv, cu.public_key_from_bytes(server_share.p256_pub)
                )
        except ValueError as exc:
            raise HandshakeError(f"key agreement failed: {exc}") from exc

        derived = hop2_v2_derive(
            selected_suite=selected,
            ss_mlkem768=ss_mlkem,
            ss_classical=ss_classical,
            client_id=self._gateway_id,
            offered_suites=offered,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            client_share=client_share,
            server_share=server_share,
            mlkem768_ct=mlkem_ct,
            session_id=session_id,
            nonce_prefix=nonce_prefix,
        )

        # We SEND on the client->server key. key_s2c stays unused while the
        # cloud's responses are plaintext, but deriving it separately means a
        # future encrypted response cannot reuse our sending key.
        self._sender = cu.AeadSender(derived.key_c2s, session_id, nonce_prefix)
        self._session_id = session_id
        self._expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        self._max_records = max_records
        self._sent = 0
        self._suite = selected

        if is_post_quantum(selected):
            self.handshakes_hybrid += 1
            self._log.info(
                "hop2 session established suite=%s (post-quantum) session=%s expires=%s",
                selected, session_id.hex()[:12], expires_at,
            )
        else:
            self.handshakes_classical += 1
            self._log.warning(
                "hop2 session established suite=%s -- CLASSICAL, no post-quantum "
                "protection (policy=%s, offered=[%s]) session=%s",
                selected, self._policy.value, canonical_suites(list(offered)),
                session_id.hex()[:12],
            )

    # ------------------------------------------------------------------ send

    def send(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Encrypt and forward one envelope, re-handshaking if needed."""
        if self._needs_handshake():
            self.handshake()

        result = self._send_once(envelope)
        if result.get("reason") == "session_expired":
            self._log.info("hop2 session gone, re-handshaking")
            self.handshake()
            result = self._send_once(envelope)
        return result

    def _send_once(self, envelope: dict[str, Any]) -> dict[str, Any]:
        if self._sender is None or self._session_id is None:
            raise HandshakeError("no established session; call handshake() first")
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


def _encode_share(suite: str, share: KeyShare) -> dict[str, str]:
    if suite == SUITE_HYBRID:
        return {
            "x25519_pub": b64e(share.x25519_pub),
            "mlkem768_ek": b64e(share.mlkem768_ek),
        }
    return {"eph_pub": b64e(share.p256_pub)}


def _reason_of(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return "unparseable"
    if isinstance(body, dict):
        return str(body.get("detail") or body.get("reason") or "unknown")
    return "unknown"
