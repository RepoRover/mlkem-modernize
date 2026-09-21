"""Edge gateway.

The gateway terminates the device's session and relays each reading onward to
the cloud over a separate session. Because the two links are cryptographically
independent, the upstream link can be modernized without the device -- which
cannot be changed -- knowing anything about it.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse

import cryptosuite as cs
import nodekit
from nodekit.config import env_float, env_int, env_path, env_str
from services.gateway.upstream import LegacyUpstream, UpstreamError
from wire.frames import DataFrame, FrameError, HandshakeRequest

SERVICE = "gateway"

log = nodekit.configure(SERVICE, env_str("LOG_LEVEL", "INFO"))

app = FastAPI(title="PQC Edge Gateway", version="0.1.0")

_private_key = cs.load_or_create_rsa(env_path("GATEWAY_KEY_PATH", "run/gateway/gateway_rsa.pem"))
_legacy_server = cs.LegacyServer(_private_key)
_upstream = LegacyUpstream(
    env_str("CLOUD_URL", "http://cloud:8000"),
    timeout=env_float("UPSTREAM_TIMEOUT_SECONDS", 5.0),
)

# Maps a device session to the independent upstream session that relays it.
_sessions: nodekit.SessionStore = nodekit.SessionStore(
    ttl_seconds=env_int("SESSION_TTL_SECONDS", 900),
    max_entries=env_int("SESSION_MAX_ENTRIES", 512),
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE}


@app.get("/readyz")
def readyz() -> JSONResponse:
    return JSONResponse({"status": "ready", "sessions": len(_sessions)})


@app.get("/capabilities")
def capabilities() -> dict[str, Any]:
    report = cs.probe().to_dict()
    report["downstream_suite"] = _legacy_server.suite
    report["upstream_suite"] = _upstream.suite
    return report


@app.get("/legacy/pubkey")
def legacy_pubkey() -> Response:
    pem = cs.serialize_public_key(_legacy_server.public_key)
    return Response(content=pem, media_type="application/x-pem-file")


@app.post("/legacy/session")
def legacy_session(body: dict[str, Any]) -> dict[str, str]:
    try:
        request = HandshakeRequest.from_dict(body)
        downstream = _legacy_server.accept(request)
    except FrameError as exc:
        log.warning("rejected device handshake", extra={"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        upstream_id, upstream = _upstream.open_session()
    except UpstreamError as exc:
        log.error("upstream handshake failed", extra={"error": str(exc)})
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    _sessions.put(request.session_id, (downstream, upstream))
    log.info(
        "relay session established",
        extra={
            "session_id": request.session_id,
            "upstream_session_id": upstream_id,
            "downstream_suite": request.suite,
            "upstream_suite": _upstream.suite,
        },
    )
    return {"session_id": request.session_id, "suite": request.suite}


@app.post("/legacy/frames")
def legacy_frame(body: dict[str, Any]) -> dict[str, Any]:
    try:
        frame = DataFrame.from_dict(body)
    except FrameError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        downstream, upstream = _relay_for(frame.session_id)
    except nodekit.SessionNotFound:
        raise HTTPException(status_code=409, detail="unknown or expired session") from None

    try:
        plaintext = downstream.open(frame)
    except FrameError as exc:
        log.warning(
            "device frame rejected",
            extra={"session_id": frame.session_id, "seq": frame.seq, "error": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Re-encrypt under the upstream session rather than forwarding the original
    # frame: the two links are separate cryptographic contexts, which is what
    # allows them to use different suites.
    try:
        _upstream.send(upstream.seal(plaintext))
    except UpstreamError as exc:
        log.error(
            "relay to cloud failed",
            extra={"session_id": frame.session_id, "seq": frame.seq, "error": str(exc)},
        )
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    log.info(
        "frame relayed",
        extra={
            "session_id": frame.session_id,
            "seq": frame.seq,
            "downstream_suite": frame.suite,
            "upstream_suite": _upstream.suite,
        },
    )
    return {"relayed": True, "seq": frame.seq}


def _relay_for(session_id: str) -> tuple[cs.RecordSession, cs.RecordSession]:
    return _sessions.get(session_id)
