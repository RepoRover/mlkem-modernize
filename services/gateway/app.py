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

import pqcnode
import pqcsuite as cs
from pqcnode.config import env_float, env_int, env_path, env_str
from pqcwire.frames import DataFrame, FrameError, HandshakeRequest
from services import metrics
from services.gateway.upstream import UpstreamError, build_upstream

SERVICE = "gateway"

log = pqcnode.configure(SERVICE, env_str("LOG_LEVEL", "INFO"))

app = FastAPI(title="PQC Edge Gateway", version="0.1.0")

_private_key = cs.load_or_create_rsa(env_path("GATEWAY_KEY_PATH", "run/gateway/gateway_rsa.pem"))
_legacy_server = cs.LegacyServer(_private_key)
# UPSTREAM_SUITE is the migration switch: flipping it from legacy to hybrid
# modernizes the cloud-facing link without the device knowing anything changed.
_upstream = build_upstream(
    env_str("CLOUD_URL", "http://cloud:8000"),
    env_str("UPSTREAM_SUITE", "auto"),
    timeout=env_float("UPSTREAM_TIMEOUT_SECONDS", 5.0),
)

metrics.record_suite(SERVICE, "downstream", _legacy_server.suite)
metrics.record_suite(SERVICE, "upstream", _upstream.suite)

log.info(
    "gateway started",
    extra={
        "downstream_suite": _legacy_server.suite,
        "upstream_suite": _upstream.suite,
        "supported_suites": cs.supported_suites(),
    },
)

# Maps a device session to the independent upstream session that relays it.
_sessions: pqcnode.SessionStore[tuple[cs.RecordSession, cs.RecordSession]] = pqcnode.SessionStore(
    ttl_seconds=env_int("SESSION_TTL_SECONDS", 900),
    max_entries=env_int("SESSION_MAX_ENTRIES", 512),
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE}


@app.get("/readyz")
def readyz() -> JSONResponse:
    return JSONResponse({"status": "ready", "sessions": len(_sessions)})


@app.get("/metrics")
def prometheus_metrics() -> Response:
    metrics.ACTIVE_SESSIONS.labels(service=SERVICE).set(len(_sessions))
    body, content_type = metrics.render()
    return Response(content=body, media_type=content_type)


@app.get("/capabilities")
def capabilities() -> dict[str, Any]:
    report = cs.probe().to_dict()
    report["downstream_suite"] = _legacy_server.suite
    report["upstream_suite"] = _upstream.suite
    report["brokering"] = _legacy_server.suite != _upstream.suite
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
        metrics.record_handshake(SERVICE, str(body.get("suite", "unknown")), "rejected")
        log.warning("rejected device handshake", extra={"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        upstream_id, upstream = _upstream.open_session()
    except UpstreamError as exc:
        metrics.record_handshake(SERVICE, _upstream.suite, "upstream_failed")
        log.error("upstream handshake failed", extra={"error": str(exc)})
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    metrics.record_handshake(SERVICE, request.suite, "established")
    metrics.record_handshake(SERVICE, _upstream.suite, "established")

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
    except pqcnode.SessionNotFound:
        raise HTTPException(status_code=409, detail="unknown or expired session") from None

    try:
        plaintext = downstream.open(frame)
    except FrameError as exc:
        metrics.record_frame(SERVICE, frame.suite, "rejected")
        log.warning(
            "device frame rejected",
            extra={"session_id": frame.session_id, "seq": frame.seq, "error": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Re-encrypt under the upstream session rather than forwarding the original
    # frame: the two links are separate cryptographic contexts, which is what
    # allows them to use different suites.
    metrics.record_frame(SERVICE, frame.suite, "accepted")
    try:
        with metrics.timed(metrics.CRYPTO_OPERATION, service=SERVICE, operation="reseal_upstream"):
            resealed = upstream.seal(plaintext)
        _upstream.send(resealed)
    except UpstreamError as exc:
        metrics.record_frame(SERVICE, _upstream.suite, "upstream_failed")
        log.error(
            "relay to cloud failed",
            extra={"session_id": frame.session_id, "seq": frame.seq, "error": str(exc)},
        )
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    metrics.record_frame(SERVICE, _upstream.suite, "accepted")
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
