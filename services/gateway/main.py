"""Edge gateway -- hop 1 server and hop 2 client.

Receives readings from the legacy device over the cruftier hop 1 channel,
validates them, and forwards them to the cloud over the clean hop 2 channel.

The gateway is a decrypt/re-encrypt point: plaintext readings exist in its
memory. This is not end-to-end confidentiality, and it is what makes a staged
PQC migration possible at all -- the device never has to change.
"""

from __future__ import annotations

import binascii
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from ..common import cryptoutil as cu
from ..common.config import (
    DEFAULT_MAX_RECORDS_PER_SESSION,
    DEFAULT_SESSION_TTL_SECONDS,
    env_int,
    env_str,
    setup_logging,
)
from ..common.handshake import HandshakeError, hop1_derive
from ..common.sessions import ServerSession, SessionStore, iso, utc_now
from ..common.suites import Policy
from ..common.weather import ValidationError, validate_reading
from ..common.wire import HOP_DEVICE_GATEWAY, PROTOCOL, b64d, b64e
from .cloud_client import CloudClient

log = setup_logging("gateway")

SUITE_HOP1 = "ECDH-P256-static-static+AES-256-GCM"


def create_app(
    keys_dir: str,
    cloud_url: str,
    gateway_id: str = "gw-01",
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    max_records: int = DEFAULT_MAX_RECORDS_PER_SESSION,
    cloud_client: CloudClient | None = None,
    policy: Policy = Policy.PREFER,
) -> FastAPI:
    keys = Path(keys_dir)
    gateway_ecdh_priv = cu.load_private_key(keys / "gateway_ecdh_priv.pem")
    # Device registry: the device's static ECDH public key IS its identity on
    # hop 1. No certificates, no revocation -- legacy firmware reality.
    device_registry = {"device-berlin-01": cu.load_public_key(keys / "device_ecdh_pub.pem")}

    if policy is Policy.CLASSICAL_ONLY:
        log.warning(
            "PQC POLICY IS 'classical-only' -- the gateway will not offer "
            "post-quantum key establishment to the cloud. Explicit opt-out."
        )

    if cloud_client is None:
        cloud_client = CloudClient(
            base_url=cloud_url,
            gateway_id=gateway_id,
            signing_key=cu.load_private_key(keys / "gateway_ecdsa_priv.pem"),
            cloud_public_key=cu.load_public_key(keys / "cloud_ecdsa_pub.pem"),
            log=log,
            policy=policy,
        )

    sessions = SessionStore(ttl_seconds=ttl_seconds, max_records=max_records)
    counters = {"accepted": 0, "rejected": 0, "forwarded": 0, "forward_failed": 0,
                "handshakes": 0}

    app = FastAPI(title="Weather Edge Gateway (legacy baseline)", version="1.0.0")
    app.state.sessions = sessions
    app.state.counters = counters
    app.state.cloud_client = cloud_client

    # ----------------------------------------------------------------- hop 1

    @app.post("/handshake")
    def handshake(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        try:
            if body.get("protocol") != PROTOCOL:
                raise HTTPException(400, "unsupported protocol")
            if body.get("hop") != HOP_DEVICE_GATEWAY:
                raise HTTPException(400, "wrong hop")

            client_id = body.get("client_id")
            if not isinstance(client_id, str) or client_id not in device_registry:
                raise HTTPException(403, "unknown device")

            client_nonce = b64d(body["client_nonce"])
        except HTTPException:
            raise
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise HTTPException(400, f"malformed ClientHello: {type(exc).__name__}") from exc

        if len(client_nonce) != cu.HANDSHAKE_NONCE_LEN:
            raise HTTPException(400, "bad client_nonce length")

        # Hop 1 has no signature to check, so this nonce table is the only thing
        # stopping a captured ClientHello from opening a second session.
        if not sessions.remember_nonce(client_nonce):
            log.warning("rejected replayed ClientHello from %s", client_id)
            raise HTTPException(409, "client_nonce already used")

        server_nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        session_id = cu.random_bytes(cu.SESSION_ID_LEN)
        nonce_prefix = cu.random_bytes(cu.NONCE_PREFIX_LEN)
        expires_at = sessions.new_expiry()

        # Static-static: no ephemeral anywhere. The same Z for every session
        # this device ever opens. Only the HKDF salt changes.
        derived = hop1_derive(
            own_static_private=gateway_ecdh_priv,
            peer_static_public=device_registry[client_id],
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            session_id=session_id,
            nonce_prefix=nonce_prefix,
        )

        sessions.put(
            ServerSession(
                session_id=session_id,
                client_id=client_id,
                receiver=cu.AeadReceiver(derived.key, session_id, nonce_prefix),
                expires_at=expires_at,
                max_records=max_records,
                suite=SUITE_HOP1,
            )
        )
        counters["handshakes"] += 1
        log.info(
            "hop1 handshake ok device=%s session=%s expires=%s",
            client_id, session_id.hex()[:12], iso(expires_at),
        )

        # Unauthenticated ServerHello -- an on-path attacker can forge it.
        # Deliberate hop 1 weakness; hop 2 signs its ServerHello.
        return {
            "protocol": PROTOCOL,
            "session_id": b64e(session_id),
            "server_nonce": b64e(server_nonce),
            "nonce_prefix": b64e(nonce_prefix),
            "expires_at": iso(expires_at),
            "max_records": max_records,
        }

    @app.post("/ingest")
    def ingest(body: dict[str, Any] = Body(...)) -> JSONResponse:
        def reject(status: int, reason: str, seq: Any = None) -> JSONResponse:
            counters["rejected"] += 1
            return JSONResponse(
                status_code=status, content={"status": "rejected", "seq": seq, "reason": reason}
            )

        try:
            session_id = b64d(body["session_id"])
            seq = body["seq"]
            nonce = b64d(body["nonce"])
            ciphertext = b64d(body["ct"])
        except (KeyError, TypeError, ValueError, binascii.Error):
            return reject(400, "malformed_message")

        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            return reject(400, "malformed_message")

        session = sessions.get(session_id)
        if session is None:
            return reject(409, "session_expired", seq)

        try:
            plaintext = session.receiver.decrypt(seq, nonce, ciphertext)
        except cu.ReplayRejected:
            log.warning("hop1 replay session=%s seq=%s", session_id.hex()[:12], seq)
            return reject(400, "replay", seq)
        except InvalidTag:
            # On hop 1 this is also what an impersonating device looks like:
            # authentication is implicit, so a wrong key fails here, not earlier.
            log.warning("hop1 bad tag session=%s seq=%s", session_id.hex()[:12], seq)
            return reject(400, "bad_tag", seq)

        try:
            payload = json.loads(plaintext)
            reading = validate_reading(payload)
            device_id = payload.get("device_id")
            if not isinstance(device_id, str):
                raise ValidationError("missing or non-string device_id")
        except (json.JSONDecodeError, TypeError) as exc:
            return reject(400, f"malformed_payload:{type(exc).__name__}", seq)
        except ValidationError as exc:
            log.warning("hop1 validation failed session=%s seq=%s: %s",
                        session_id.hex()[:12], seq, exc)
            return reject(400, "validation_failed", seq)

        # The session was opened by a device whose static key we looked up, so
        # the payload's device_id must match it or someone is relaying.
        if device_id != session.client_id:
            log.warning("hop1 device_id mismatch session=%s", session_id.hex()[:12])
            return reject(400, "device_id_mismatch", seq)

        session.accepted += 1
        counters["accepted"] += 1

        envelope = {
            "gateway_id": gateway_id,
            "device_id": device_id,
            "reading": reading.to_dict(),
            "station": payload.get("station"),
            "received_at": iso(utc_now()),
            "device_hop": {"verified": True, "suite": SUITE_HOP1},
        }

        try:
            result = cloud_client.send(envelope)
        except (HandshakeError, OSError) as exc:
            # The reading is lost. The baseline has no store-and-forward queue,
            # which is a real availability weakness -- see docs/ARCHITECTURE.md.
            counters["forward_failed"] += 1
            # log.error, not log.exception: the cause is in the message and a
            # traceback per dropped reading would bury the log.
            log.error("hop2 forward failed seq=%s: %s", seq, exc)  # noqa: TRY400
            return JSONResponse(
                status_code=502,
                content={
                    "status": "accepted_not_forwarded",
                    "seq": seq,
                    "reason": "cloud_unreachable",
                },
            )

        if result.get("status") == "accepted":
            counters["forwarded"] += 1
            log.info("relayed session=%s seq=%s date=%s", session_id.hex()[:12], seq, reading.date)
        else:
            counters["forward_failed"] += 1
            log.warning("cloud rejected seq=%s reason=%s", seq, result.get("reason"))

        return JSONResponse(
            content={"status": "accepted", "seq": seq, "cloud": result.get("status")}
        )

    @app.get("/stats")
    def stats() -> dict[str, Any]:
        return {
            "gateway_id": gateway_id,
            "sessions_active": sessions.active,
            "messages": dict(counters),
            "hop1": {"suite": SUITE_HOP1, "post_quantum": False},
            "hop2": {
                "policy": policy.value,
                "current_suite": cloud_client.suite,
                "handshakes_hybrid": cloud_client.handshakes_hybrid,
                "handshakes_classical": cloud_client.handshakes_classical,
            },
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "gateway",
            "hop1_suite": SUITE_HOP1,
            "hop2_policy": policy.value,
            "hop2_suite": cloud_client.suite,
        }

    return app


def build_default_app() -> FastAPI:
    return create_app(
        keys_dir=env_str("KEYS_DIR", "keys"),
        cloud_url=env_str("CLOUD_URL", "http://cloud:8000"),
        gateway_id=env_str("GATEWAY_ID", "gw-01"),
        ttl_seconds=env_int("SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS),
        max_records=env_int("MAX_RECORDS_PER_SESSION", DEFAULT_MAX_RECORDS_PER_SESSION),
        # The gateway PREFERS PQC by default rather than requiring it, so that
        # phase 1 of the migration can run against a cloud that is still being
        # rolled out. The cloud defaults to 'require'; it is the enforcement point.
        policy=Policy.parse(env_str("PQC_POLICY", Policy.PREFER.value)),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        build_default_app(),
        # Container-internal bind; the gateway Service is ClusterIP-only
        # and its ingest port is never published outside the cluster.
        host="0.0.0.0",  # noqa: S104  # nosec B104
        port=env_int("PORT", 8000),
        log_level=env_str("LOG_LEVEL", "info").lower(),
    )
