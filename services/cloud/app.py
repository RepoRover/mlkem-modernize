"""Cloud telemetry service.

Accepts telemetry over either cipher suite. The legacy suite can be switched
off with ALLOW_LEGACY_SUITE=false, which is how a fleet migration is completed:
once every gateway speaks the post-quantum suite, the cloud stops accepting
quantum-vulnerable traffic and the refusal shows up in the logs rather than
going unnoticed.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse

import cryptosuite as cs
import nodekit
from nodekit.config import env_bool, env_int, env_path, env_str
from services.cloud.store import ReadingStore
from wire.frames import DataFrame, FrameError, HandshakeRequest
from wire.protocol import HYBRID_PQC, LEGACY_RSA, suite_spec
from wire.telemetry import DatasetError, WeatherReading

SERVICE = "cloud"

log = nodekit.configure(SERVICE, env_str("LOG_LEVEL", "INFO"))

app = FastAPI(title="PQC Telemetry Cloud", version="0.2.0")

_store = ReadingStore(env_path("CLOUD_DB_PATH", "run/cloud/readings.db"))
_allow_legacy = env_bool("ALLOW_LEGACY_SUITE", True)

_legacy_server = cs.LegacyServer(
    cs.load_or_create_rsa(env_path("CLOUD_KEY_PATH", "run/cloud/cloud_rsa.pem"))
)
_identity_key = cs.load_or_create_identity(
    env_path("CLOUD_IDENTITY_PATH", "run/cloud/cloud_mldsa.key")
)
_hybrid_server = cs.HybridServer(_identity_key, ttl_seconds=env_int("OFFER_TTL_SECONDS", 60))

_sessions: nodekit.SessionStore = nodekit.SessionStore(
    ttl_seconds=env_int("SESSION_TTL_SECONDS", 900),
    max_entries=env_int("SESSION_MAX_ENTRIES", 512),
)

log.info(
    "cloud started",
    extra={"allow_legacy_suite": _allow_legacy, "supported_suites": cs.supported_suites()},
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE}


@app.get("/readyz")
def readyz() -> JSONResponse:
    try:
        _store.total()
    except Exception as exc:
        log.error("readiness probe failed", extra={"error": str(exc)})
        return JSONResponse({"status": "unready"}, status_code=503)
    return JSONResponse({"status": "ready", "sessions": len(_sessions)})


@app.get("/capabilities")
def capabilities() -> dict[str, Any]:
    report = cs.probe().to_dict()
    report["allow_legacy_suite"] = _allow_legacy
    report["accepted_suites"] = cs.supported_suites() if _allow_legacy else [HYBRID_PQC]
    return report


# --------------------------------------------------------------------------
# Legacy suite
# --------------------------------------------------------------------------


@app.get("/legacy/pubkey")
def legacy_pubkey() -> Response:
    _require_legacy_allowed()
    pem = cs.serialize_public_key(_legacy_server.public_key)
    return Response(content=pem, media_type="application/x-pem-file")


@app.post("/legacy/session")
def legacy_session(body: dict[str, Any]) -> dict[str, str]:
    _require_legacy_allowed()
    return _establish(body, _legacy_server.accept)


@app.post("/legacy/frames")
def legacy_frame(body: dict[str, Any]) -> dict[str, Any]:
    _require_legacy_allowed()
    return _accept_frame(body)


# --------------------------------------------------------------------------
# Post-quantum suite
# --------------------------------------------------------------------------


@app.get("/pqc/identity")
def pqc_identity() -> dict[str, str]:
    """The long-term ML-DSA public key used to sign ephemeral offers."""
    from wire.frames import b64e

    return {
        "algorithm": "ML-DSA-65",
        "public_key": b64e(cs.serialize_identity_public(_hybrid_server.identity_public_key)),
    }


@app.get("/pqc/offer")
def pqc_offer() -> dict[str, str]:
    """Issue a signed, single-use set of ephemeral KEM public keys.

    Ephemeral keys are what give the modernized link forward secrecy: they are
    discarded after one handshake, so a later compromise of the long-term
    identity key reveals nothing about past sessions.
    """
    try:
        offer = _hybrid_server.make_offer()
    except cs.CapabilityError as exc:
        log.error("cannot issue a post-quantum offer", extra={"error": str(exc)})
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    log.info("offer issued", extra={"key_id": offer.key_id, "suite": HYBRID_PQC})
    return offer.to_dict()


@app.post("/pqc/session")
def pqc_session(body: dict[str, Any]) -> dict[str, str]:
    return _establish(body, _hybrid_server.accept)


@app.post("/pqc/frames")
def pqc_frame(body: dict[str, Any]) -> dict[str, Any]:
    return _accept_frame(body)


# --------------------------------------------------------------------------
# Query
# --------------------------------------------------------------------------


@app.get("/readings")
def readings(limit: int = 50, suite: str = "") -> dict[str, Any]:
    if not 1 <= limit <= 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    counts = _store.counts_by_suite()
    return {
        "total": _store.total(),
        "by_suite": counts,
        "quantum_vulnerable_frames": counts.get(LEGACY_RSA, 0),
        "readings": _store.query(limit=limit, suite=suite or None),
    }


# --------------------------------------------------------------------------
# Shared handling
# --------------------------------------------------------------------------


def _require_legacy_allowed() -> None:
    if not _allow_legacy:
        log.warning("rejected legacy request: policy forbids the legacy suite")
        raise HTTPException(
            status_code=403,
            detail=f"the legacy suite is disabled; migrate to {HYBRID_PQC}",
        )


def _establish(body: dict[str, Any], accept) -> dict[str, str]:
    try:
        request = HandshakeRequest.from_dict(body)
        session = accept(request)
    except FrameError as exc:
        log.warning("rejected handshake", extra={"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except cs.CapabilityError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc

    _sessions.put(request.session_id, session)
    spec = suite_spec(request.suite)
    log.info(
        "session established",
        extra={
            "session_id": request.session_id,
            "suite": request.suite,
            "quantum_resistant": spec.quantum_resistant,
        },
    )
    return {"session_id": request.session_id, "suite": request.suite}


def _accept_frame(body: dict[str, Any]) -> dict[str, Any]:
    try:
        frame = DataFrame.from_dict(body)
    except FrameError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        session = _sessions.get(frame.session_id)
    except nodekit.SessionNotFound:
        raise HTTPException(status_code=409, detail="unknown or expired session") from None

    try:
        plaintext = session.open(frame)
    except FrameError as exc:
        log.warning(
            "frame rejected",
            extra={"session_id": frame.session_id, "seq": frame.seq, "error": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        reading = WeatherReading.from_dict(json.loads(plaintext.decode("utf-8")))
    except (UnicodeDecodeError, ValueError, DatasetError) as exc:
        raise HTTPException(status_code=422, detail="payload is not a weather reading") from exc

    _store.insert(frame.session_id, frame.seq, frame.suite, reading)
    log.info(
        "reading stored",
        extra={
            "session_id": frame.session_id,
            "seq": frame.seq,
            "suite": frame.suite,
            "quantum_resistant": suite_spec(frame.suite).quantum_resistant,
            "date": reading.date,
        },
    )
    return {"accepted": True, "seq": frame.seq}
