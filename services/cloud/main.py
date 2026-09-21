"""Cloud service -- hop 2 server, storage, and the read API.

Hop 2 (gateway -> cloud) is the CLEAN classical baseline:
ephemeral-ephemeral ECDH P-256 with mutual ECDSA authentication. This is the
hop that later gains X25519 + ML-KEM-768, so it is built to make that swap a
change to one derivation function rather than a redesign.
"""

from __future__ import annotations

import binascii
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from ..common import cryptoutil as cu
from ..common.config import (
    DEFAULT_MAX_RECORDS_PER_SESSION,
    DEFAULT_SESSION_TTL_SECONDS,
    env_int,
    env_str,
    setup_logging,
)
from ..common.handshake import hop2_client_transcript, hop2_derive, hop2_server_transcript
from ..common.sessions import ServerSession, SessionStore, iso, utc_now
from ..common.weather import ValidationError, validate_reading
from ..common.wire import HOP_GATEWAY_CLOUD, PROTOCOL, b64d, b64e
from .storage import Storage

log = setup_logging("cloud")


def create_app(
    keys_dir: str,
    db_path: str,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    max_records: int = DEFAULT_MAX_RECORDS_PER_SESSION,
) -> FastAPI:
    keys = Path(keys_dir)
    cloud_ecdsa_priv = cu.load_private_key(keys / "cloud_ecdsa_priv.pem")
    # Registry of gateways we will talk to. One entry in the baseline; a real
    # deployment would look this up from a directory with revocation.
    gateway_registry = {"gw-01": cu.load_public_key(keys / "gateway_ecdsa_pub.pem")}

    storage = Storage(db_path)
    sessions = SessionStore(ttl_seconds=ttl_seconds, max_records=max_records)
    counters = {"accepted": 0, "rejected": 0, "handshakes": 0}

    app = FastAPI(title="Weather Cloud (legacy baseline)", version="1.0.0")
    app.state.storage = storage
    app.state.sessions = sessions
    app.state.counters = counters

    # ----------------------------------------------------------------- hop 2

    @app.post("/handshake")
    def handshake(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        try:
            if body.get("protocol") != PROTOCOL:
                raise HTTPException(400, "unsupported protocol")
            if body.get("hop") != HOP_GATEWAY_CLOUD:
                raise HTTPException(400, "wrong hop")

            client_id = body.get("client_id")
            if not isinstance(client_id, str) or client_id not in gateway_registry:
                raise HTTPException(403, "unknown gateway")

            client_nonce = b64d(body["client_nonce"])
            client_eph_pub_raw = b64d(body["eph_pub"])
            signature = b64d(body["sig"])
        except HTTPException:
            raise
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise HTTPException(400, f"malformed ClientHello: {type(exc).__name__}") from exc

        if len(client_nonce) != cu.HANDSHAKE_NONCE_LEN:
            raise HTTPException(400, "bad client_nonce length")

        # Replay protection for the handshake itself: a captured ClientHello
        # cannot be used to open a second session.
        if not sessions.remember_nonce(client_nonce):
            log.warning("rejected replayed ClientHello from %s", client_id)
            raise HTTPException(409, "client_nonce already used")

        # Authenticate the gateway before doing any key agreement work.
        transcript = hop2_client_transcript(client_id, client_nonce, client_eph_pub_raw)
        if not cu.verify(gateway_registry[client_id], signature, transcript):
            log.warning("rejected bad ClientHello signature from %s", client_id)
            raise HTTPException(403, "signature verification failed")

        try:
            # Rejects points that are not on P-256 (invalid-curve defence).
            client_eph_pub = cu.public_key_from_bytes(client_eph_pub_raw)
        except ValueError as exc:
            raise HTTPException(400, "invalid ephemeral public key") from exc

        # Fresh ephemeral per session -- this is what gives hop 2 forward secrecy.
        server_eph_priv = cu.generate_private_key()
        server_eph_pub_raw = cu.public_key_to_bytes(server_eph_priv.public_key())

        server_nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        session_id = cu.random_bytes(cu.SESSION_ID_LEN)
        nonce_prefix = cu.random_bytes(cu.NONCE_PREFIX_LEN)
        expires_at = sessions.new_expiry()
        expires_at_iso = iso(expires_at)

        derived = hop2_derive(
            own_ephemeral_private=server_eph_priv,
            peer_ephemeral_public=client_eph_pub,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            client_eph_pub=client_eph_pub_raw,
            server_eph_pub=server_eph_pub_raw,
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
            )
        )
        counters["handshakes"] += 1

        # Sign the whole transcript, including the client's contribution. This is
        # the explicit server authentication that replaces what TLS would give us.
        server_transcript = hop2_server_transcript(
            client_id=client_id,
            client_nonce=client_nonce,
            client_eph_pub=client_eph_pub_raw,
            session_id=session_id,
            server_nonce=server_nonce,
            server_eph_pub=server_eph_pub_raw,
            nonce_prefix=nonce_prefix,
            expires_at=expires_at_iso,
            max_records=max_records,
        )

        log.info(
            "hop2 handshake ok gateway=%s session=%s expires=%s",
            client_id,
            session_id.hex()[:12],
            expires_at_iso,
        )

        return {
            "protocol": PROTOCOL,
            "session_id": b64e(session_id),
            "server_nonce": b64e(server_nonce),
            "eph_pub": b64e(server_eph_pub_raw),
            "nonce_prefix": b64e(nonce_prefix),
            "expires_at": expires_at_iso,
            "max_records": max_records,
            "sig": b64e(cu.sign(cloud_ecdsa_priv, server_transcript)),
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
            log.warning("hop2 replay session=%s seq=%s", session_id.hex()[:12], seq)
            return reject(400, "replay", seq)
        except InvalidTag:
            log.warning("hop2 bad tag session=%s seq=%s", session_id.hex()[:12], seq)
            return reject(400, "bad_tag", seq)

        try:
            envelope = json.loads(plaintext)
            reading = validate_reading(envelope["reading"])
            device_id = envelope["device_id"]
            gateway_id = envelope["gateway_id"]
            received_at = envelope["received_at"]
            if not all(isinstance(v, str) for v in (device_id, gateway_id, received_at)):
                raise ValidationError("envelope field is not a string")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            log.warning("hop2 malformed envelope session=%s seq=%s", session_id.hex()[:12], seq)
            return reject(400, f"malformed_envelope:{type(exc).__name__}", seq)
        except ValidationError as exc:
            # Safe to log: validate_reading names the field, never the values.
            log.warning("hop2 validation failed session=%s seq=%s: %s",
                        session_id.hex()[:12], seq, exc)
            return reject(400, "validation_failed", seq)

        outcome = storage.store(
            device_id=device_id,
            gateway_id=gateway_id,
            reading=reading.to_dict(),
            received_at=received_at,
            stored_at=iso(utc_now()),
        )
        session.accepted += 1
        counters["accepted"] += 1

        log.info(
            "hop2 %s session=%s seq=%s device=%s date=%s",
            outcome, session_id.hex()[:12], seq, device_id, reading.date,
        )
        return JSONResponse(content={"status": "accepted", "seq": seq, "outcome": outcome})

    # -------------------------------------------------------------- read API
    # No authentication and no rate limiting -- baseline weakness, see docs.

    @app.get("/readings")
    def get_readings(
        limit: int = Query(100, ge=1, le=1000),
        since: str | None = Query(None, description="ISO date, inclusive lower bound"),
        device_id: str | None = Query(None),
    ) -> dict[str, Any]:
        rows = storage.list_readings(limit=limit, since=since, device_id=device_id)
        return {"count": len(rows), "readings": rows}

    @app.get("/readings/{date}")
    def get_reading(date: str, device_id: str | None = Query(None)) -> dict[str, Any]:
        rows = storage.get_by_date(date, device_id=device_id)
        if not rows:
            raise HTTPException(404, "no reading for that date")
        return {"count": len(rows), "readings": rows}

    @app.get("/stats")
    def get_stats() -> dict[str, Any]:
        return {
            "storage": storage.stats(),
            "sessions_active": sessions.active,
            "messages": dict(counters),
        }

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "cloud", "suite": "ECDHE-P256+ECDSA-P256+AES-256-GCM"}

    return app


def build_default_app() -> FastAPI:
    return create_app(
        keys_dir=env_str("KEYS_DIR", "keys"),
        db_path=env_str("DB_PATH", "/data/readings.db"),
        ttl_seconds=env_int("SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS),
        max_records=env_int("MAX_RECORDS_PER_SESSION", DEFAULT_MAX_RECORDS_PER_SESSION),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        build_default_app(),
        host="0.0.0.0",  # noqa: S104 - container-internal, published selectively by compose
        port=env_int("PORT", 8000),
        log_level=env_str("LOG_LEVEL", "info").lower(),
    )
