"""Cloud telemetry service.

At this baseline the cloud speaks only the legacy suite, so the entire path
from device to database is protected by RSA key transport. That is the
weakness the modernization removes.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse

import cryptosuite as cs
import nodekit
from nodekit.config import env_int, env_path, env_str
from services.cloud.store import ReadingStore
from wire.frames import DataFrame, FrameError, HandshakeRequest
from wire.telemetry import DatasetError, WeatherReading

SERVICE = "cloud"

log = nodekit.configure(SERVICE, env_str("LOG_LEVEL", "INFO"))

app = FastAPI(title="PQC Telemetry Cloud", version="0.1.0")

_store = ReadingStore(env_path("CLOUD_DB_PATH", "run/cloud/readings.db"))
_private_key = cs.load_or_create_rsa(env_path("CLOUD_KEY_PATH", "run/cloud/cloud_rsa.pem"))
_legacy_server = cs.LegacyServer(_private_key)
_sessions: nodekit.SessionStore = nodekit.SessionStore(
    ttl_seconds=env_int("SESSION_TTL_SECONDS", 900),
    max_entries=env_int("SESSION_MAX_ENTRIES", 512),
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
    return cs.probe().to_dict()


@app.get("/legacy/pubkey")
def legacy_pubkey() -> Response:
    pem = cs.serialize_public_key(_legacy_server.public_key)
    return Response(content=pem, media_type="application/x-pem-file")


@app.post("/legacy/session")
def legacy_session(body: dict[str, Any]) -> dict[str, str]:
    try:
        request = HandshakeRequest.from_dict(body)
        session = _legacy_server.accept(request)
    except FrameError as exc:
        log.warning("rejected handshake", extra={"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _sessions.put(request.session_id, session)
    log.info(
        "session established",
        extra={"session_id": request.session_id, "suite": request.suite},
    )
    return {"session_id": request.session_id, "suite": request.suite}


@app.post("/legacy/frames")
def legacy_frame(body: dict[str, Any]) -> dict[str, Any]:
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
            "date": reading.date,
        },
    )
    return {"accepted": True, "seq": frame.seq}


@app.get("/readings")
def readings(limit: int = 50, suite: str = "") -> dict[str, Any]:
    if not 1 <= limit <= 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    return {
        "total": _store.total(),
        "by_suite": _store.counts_by_suite(),
        "readings": _store.query(limit=limit, suite=suite or None),
    }
