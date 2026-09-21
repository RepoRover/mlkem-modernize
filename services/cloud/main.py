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
from ..common.handshake import (
    KeyShare,
    hop2_client_transcript,
    hop2_derive,
    hop2_server_transcript,
    hop2_v2_client_transcript,
    hop2_v2_derive,
    hop2_v2_server_transcript,
)
from ..common.sessions import ServerSession, SessionStore, iso, utc_now
from ..common.suites import (
    SUITE_CLASSICAL,
    SUITE_HYBRID,
    NegotiationError,
    Policy,
    canonical_suites,
    is_post_quantum,
    negotiate,
)
from ..common.weather import ValidationError, validate_reading
from ..common.wire import HOP_GATEWAY_CLOUD, PROTOCOL, PROTOCOL_V2, b64d, b64e
from .storage import Storage

log = setup_logging("cloud")


def create_app(
    keys_dir: str,
    db_path: str,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    max_records: int = DEFAULT_MAX_RECORDS_PER_SESSION,
    policy: Policy = Policy.REQUIRE,
) -> FastAPI:
    keys = Path(keys_dir)
    cloud_ecdsa_priv = cu.load_private_key(keys / "cloud_ecdsa_priv.pem")
    # Registry of gateways we will talk to. One entry in the baseline; a real
    # deployment would look this up from a directory with revocation.
    gateway_registry = {"gw-01": cu.load_public_key(keys / "gateway_ecdsa_pub.pem")}

    storage = Storage(db_path)
    sessions = SessionStore(ttl_seconds=ttl_seconds, max_records=max_records)
    counters = {
        "accepted": 0,
        "rejected": 0,
        "handshakes": 0,
        # PQC negotiation visibility. A classical handshake is never silent:
        # it is logged at WARNING and counted here. See docs/MIGRATION.md.
        "handshakes_hybrid": 0,
        "handshakes_classical": 0,
        "handshakes_downgrade_refused": 0,
        "handshakes_legacy_v1": 0,
    }

    if policy is Policy.CLASSICAL_ONLY:
        log.warning(
            "PQC POLICY IS 'classical-only' -- post-quantum key establishment is "
            "DISABLED on hop 2. This is an explicit opt-out; traffic is exposed to "
            "harvest-now-decrypt-later."
        )
    else:
        log.info("hop 2 PQC policy: %s", policy.value)

    app = FastAPI(title="Weather Cloud", version="2.0.0")
    app.state.storage = storage
    app.state.sessions = sessions
    app.state.counters = counters
    app.state.policy = policy

    # ----------------------------------------------------------------- hop 2

    @app.post("/handshake")
    def handshake(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """Version dispatch.

        A v1 gateway is still understood, so an un-upgraded edge does not break
        the moment the cloud is deployed. But under policy=require its
        classical-only offer is refused -- that is the migration working as
        intended, not an outage to be patched around.
        """
        protocol = body.get("protocol")
        if protocol == PROTOCOL_V2:
            return handshake_v2(body)
        if protocol == PROTOCOL:
            return handshake_v1(body)
        raise HTTPException(400, "unsupported protocol")

    def handshake_v1(body: dict[str, Any]) -> dict[str, Any]:
        """Pre-PQC hop 2 handshake: P-256 ECDHE, no suite negotiation.

        A v1 ClientHello can only ever mean classical-only, so it is put through
        the same policy gate as an explicit classical offer.
        """
        try:
            # Called for its side-effect: raises unless policy permits classical.
            negotiate([SUITE_CLASSICAL], policy)
        except NegotiationError as exc:
            counters["handshakes_downgrade_refused"] += 1
            log.warning(
                "REFUSED legacy v1 handshake from %s: policy=%s reason=%s",
                body.get("client_id"), policy.value, exc.reason,
            )
            raise HTTPException(403, exc.reason) from exc

        counters["handshakes_legacy_v1"] += 1
        counters["handshakes_classical"] += 1
        log.warning(
            "CLASSICAL handshake (legacy v1 peer) client=%s policy=%s -- "
            "no post-quantum protection on this session",
            body.get("client_id"), policy.value,
        )
        return _handshake_v1_classical(body)

    def _handshake_v1_classical(body: dict[str, Any]) -> dict[str, Any]:
        try:
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

    # ------------------------------------------------- hop 2 v2 (hybrid PQC)

    def handshake_v2(body: dict[str, Any]) -> dict[str, Any]:
        """Suite-negotiating handshake with hybrid X25519 + ML-KEM-768.

        Order of operations matters and is deliberate:
          1. parse           -- cheap, and rejects garbage before anything else
          2. authenticate    -- verify the gateway's signature over its OFFER
          3. negotiate       -- apply policy; refuse a downgrade here
          4. key agreement   -- only now do the expensive crypto

        Authenticating before negotiating means an off-path attacker cannot
        influence suite selection at all, and cannot make us do ML-KEM work.
        """
        try:
            if body.get("hop") != HOP_GATEWAY_CLOUD:
                raise HTTPException(400, "wrong hop")

            client_id = body.get("client_id")
            if not isinstance(client_id, str) or client_id not in gateway_registry:
                raise HTTPException(403, "unknown gateway")

            client_nonce = b64d(body["client_nonce"])
            signature = b64d(body["sig"])

            offered = body.get("offered_suites")
            if not isinstance(offered, list) or not offered:
                raise HTTPException(400, "offered_suites must be a non-empty list")
            if not all(isinstance(x, str) for x in offered):
                raise HTTPException(400, "offered_suites must be strings")
            if len(offered) > 16:
                raise HTTPException(400, "offered_suites too long")

            raw_shares = body.get("key_shares")
            if not isinstance(raw_shares, dict):
                raise HTTPException(400, "key_shares must be an object")

            client_shares: dict[str, KeyShare] = {}
            for suite in offered:
                entry = raw_shares.get(suite)
                if entry is None:
                    client_shares[suite] = KeyShare()
                    continue
                if not isinstance(entry, dict):
                    raise HTTPException(400, "key_share entry must be an object")
                client_shares[suite] = KeyShare(
                    x25519_pub=b64d(entry["x25519_pub"]) if "x25519_pub" in entry else b"",
                    mlkem768_ek=b64d(entry["mlkem768_ek"]) if "mlkem768_ek" in entry else b"",
                    p256_pub=b64d(entry["eph_pub"]) if "eph_pub" in entry else b"",
                )
        except HTTPException:
            raise
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise HTTPException(400, f"malformed ClientHello: {type(exc).__name__}") from exc

        if len(client_nonce) != cu.HANDSHAKE_NONCE_LEN:
            raise HTTPException(400, "bad client_nonce length")

        if not sessions.remember_nonce(client_nonce):
            log.warning("rejected replayed v2 ClientHello from %s", client_id)
            raise HTTPException(409, "client_nonce already used")

        # --- 2. authenticate the offer itself ---------------------------------
        # The signature covers offered_suites and every key share, so an
        # attacker who strips the hybrid suite invalidates it. This is the
        # cryptographic half of downgrade protection.
        transcript = hop2_v2_client_transcript(
            client_id=client_id,
            client_nonce=client_nonce,
            offered_suites=offered,
            shares=client_shares,
        )
        if not cu.verify(gateway_registry[client_id], signature, transcript):
            log.warning(
                "rejected v2 ClientHello signature from %s (offer may have been tampered with)",
                client_id,
            )
            raise HTTPException(403, "signature verification failed")

        # --- 3. negotiate under policy ---------------------------------------
        try:
            selected = negotiate(offered, policy)
        except NegotiationError as exc:
            counters["handshakes_downgrade_refused"] += 1
            log.warning(
                "REFUSED handshake from %s: policy=%s offered=[%s] reason=%s",
                client_id, policy.value, canonical_suites(offered), exc.reason,
            )
            raise HTTPException(403, exc.reason) from exc

        if is_post_quantum(selected):
            counters["handshakes_hybrid"] += 1
        else:
            # Never silent: WARNING plus a counter, every time.
            counters["handshakes_classical"] += 1
            log.warning(
                "CLASSICAL handshake selected client=%s policy=%s offered=[%s] -- "
                "this session has NO post-quantum protection",
                client_id, policy.value, canonical_suites(offered),
            )

        client_share = client_shares.get(selected, KeyShare())

        # --- 4. key agreement -------------------------------------------------
        server_share = KeyShare()
        mlkem_ct = b""
        ss_mlkem = b""

        try:
            if selected == SUITE_HYBRID:
                # X25519 half.
                peer_x25519 = cu.x25519_public_from_bytes(client_share.x25519_pub)
                server_x25519_priv = cu.generate_x25519_private_key()
                server_x25519_pub = cu.x25519_public_bytes(server_x25519_priv.public_key())
                ss_classical = cu.x25519_exchange(server_x25519_priv, peer_x25519)

                # ML-KEM half: the cloud encapsulates to the gateway's key.
                peer_ek = cu.mlkem768_encapsulation_key_from_bytes(client_share.mlkem768_ek)
                ss_mlkem, mlkem_ct = cu.mlkem768_encapsulate(peer_ek)

                server_share = KeyShare(x25519_pub=server_x25519_pub)
            else:
                peer_p256 = cu.public_key_from_bytes(client_share.p256_pub)
                server_p256_priv = cu.generate_private_key()
                server_p256_pub = cu.public_key_to_bytes(server_p256_priv.public_key())
                ss_classical = cu.ecdh(server_p256_priv, peer_p256)
                server_share = KeyShare(p256_pub=server_p256_pub)
        except cu.InvalidEncapsulationKey as exc:
            log.warning("invalid ML-KEM encapsulation key from %s", client_id)
            raise HTTPException(400, "invalid_encapsulation_key") from exc
        except ValueError as exc:
            raise HTTPException(400, "invalid key share") from exc

        server_nonce = cu.random_bytes(cu.HANDSHAKE_NONCE_LEN)
        session_id = cu.random_bytes(cu.SESSION_ID_LEN)
        nonce_prefix = cu.random_bytes(cu.NONCE_PREFIX_LEN)
        expires_at = sessions.new_expiry()
        expires_at_iso = iso(expires_at)

        derived = hop2_v2_derive(
            selected_suite=selected,
            ss_mlkem768=ss_mlkem,
            ss_classical=ss_classical,
            client_id=client_id,
            offered_suites=offered,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            client_share=client_share,
            server_share=server_share,
            mlkem768_ct=mlkem_ct,
            session_id=session_id,
            nonce_prefix=nonce_prefix,
        )

        sessions.put(
            ServerSession(
                session_id=session_id,
                client_id=client_id,
                # We RECEIVE on the client->server key. The server->client key
                # exists but is unused while responses are plaintext.
                receiver=cu.AeadReceiver(derived.key_c2s, session_id, nonce_prefix),
                expires_at=expires_at,
                max_records=max_records,
                suite=selected,
            )
        )
        counters["handshakes"] += 1

        server_transcript = hop2_v2_server_transcript(
            client_id=client_id,
            client_nonce=client_nonce,
            offered_suites=offered,
            client_shares=client_shares,
            selected_suite=selected,
            session_id=session_id,
            server_nonce=server_nonce,
            server_share=server_share,
            mlkem768_ct=mlkem_ct,
            nonce_prefix=nonce_prefix,
            expires_at=expires_at_iso,
            max_records=max_records,
        )

        log.info(
            "hop2 v2 handshake ok gateway=%s suite=%s session=%s expires=%s",
            client_id, selected, session_id.hex()[:12], expires_at_iso,
        )

        response: dict[str, Any] = {
            "protocol": PROTOCOL_V2,
            "selected_suite": selected,
            "session_id": b64e(session_id),
            "server_nonce": b64e(server_nonce),
            "nonce_prefix": b64e(nonce_prefix),
            "expires_at": expires_at_iso,
            "max_records": max_records,
            "sig": b64e(cu.sign(cloud_ecdsa_priv, server_transcript)),
        }
        if selected == SUITE_HYBRID:
            response["x25519_pub"] = b64e(server_share.x25519_pub)
            response["mlkem768_ct"] = b64e(mlkem_ct)
        else:
            response["eph_pub"] = b64e(server_share.p256_pub)
        return response

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
        hybrid = counters["handshakes_hybrid"]
        classical = counters["handshakes_classical"]
        total = hybrid + classical
        return {
            "storage": storage.stats(),
            "sessions_active": sessions.active,
            "messages": dict(counters),
            "pqc": {
                "policy": policy.value,
                "handshakes_hybrid": hybrid,
                "handshakes_classical": classical,
                "handshakes_downgrade_refused": counters["handshakes_downgrade_refused"],
                # The number to watch during migration: 1.0 means the whole
                # fleet is on post-quantum key establishment.
                "pqc_fraction": round(hybrid / total, 4) if total else None,
            },
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "cloud",
            "protocols": [PROTOCOL, PROTOCOL_V2],
            "suites": [SUITE_HYBRID, SUITE_CLASSICAL],
            "policy": policy.value,
        }

    return app


def build_default_app() -> FastAPI:
    return create_app(
        keys_dir=env_str("KEYS_DIR", "keys"),
        db_path=env_str("DB_PATH", "/data/readings.db"),
        ttl_seconds=env_int("SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS),
        max_records=env_int("MAX_RECORDS_PER_SESSION", DEFAULT_MAX_RECORDS_PER_SESSION),
        # The cloud requires PQC by default. An operator who needs the classical
        # path must ask for it explicitly, and it is logged loudly at startup.
        policy=Policy.parse(env_str("PQC_POLICY", Policy.REQUIRE.value)),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        build_default_app(),
        # Binding all interfaces is correct inside a container: what is
        # reachable is decided by the port mapping / k8s Service, not
        # by the bind address. Only the cloud read API is published.
        host="0.0.0.0",  # noqa: S104  # nosec B104
        port=env_int("PORT", 8000),
        log_level=env_str("LOG_LEVEL", "info").lower(),
    )
