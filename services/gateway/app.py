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
from services.gateway.upstream import UpstreamError, UpstreamSessionRejected, build_upstream

SERVICE = "gateway"

log = pqcnode.configure(SERVICE, env_str("LOG_LEVEL", "INFO"))

app = FastAPI(title="PQC Edge Gateway", version="0.1.0")

_private_key = cs.load_or_create_rsa(env_path("GATEWAY_KEY_PATH", "run/gateway/gateway_rsa.pem"))
_legacy_server = cs.LegacyServer(_private_key)
# UPSTREAM_SUITE is the migration switch: flipping it from legacy to hybrid
# modernizes the cloud-facing link without the device knowing anything changed.
# Hybrid and auto mode require a locally provisioned trust anchor. It is loaded
# before serving traffic, so a missing or malformed pin prevents startup rather
# than falling back to a network-fetched identity or to the legacy suite.
_upstream_mode = env_str("UPSTREAM_SUITE", "hybrid").strip().lower()
_hybrid_mode = _upstream_mode in {"hybrid", "auto"}
_identity_path = env_path("CLOUD_IDENTITY_PUBLIC_KEY_PATH") if _hybrid_mode else None
_gateway_identity_path = env_path("GATEWAY_IDENTITY_PATH") if _hybrid_mode else None
_upstream = build_upstream(
    env_str("CLOUD_URL", "http://cloud:8000"),
    _upstream_mode,
    timeout=env_float("UPSTREAM_TIMEOUT_SECONDS", 5.0),
    identity_path=_identity_path,
    gateway_identity_path=_gateway_identity_path,
    deadline=env_float("UPSTREAM_TOTAL_DEADLINE_SECONDS", 12.0),
    retry_attempts=env_int("UPSTREAM_RETRY_ATTEMPTS", 3),
    retry_initial=env_float("UPSTREAM_RETRY_INITIAL_SECONDS", 0.1),
    retry_max=env_float("UPSTREAM_RETRY_MAX_SECONDS", 1.0),
    max_response_bytes=env_int("UPSTREAM_MAX_RESPONSE_BYTES", 32768),
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
_session_max_entries = env_int("SESSION_MAX_ENTRIES", 512)
_sessions: pqcnode.SessionStore[tuple[cs.RecordSession, cs.RecordSession]] = pqcnode.SessionStore(
    ttl_seconds=env_int("SESSION_TTL_SECONDS", 900),
    max_entries=_session_max_entries,
    history_ttl_seconds=env_int("SESSION_ID_HISTORY_TTL_SECONDS", 1800),
    history_max_entries=env_int("SESSION_ID_HISTORY_MAX_ENTRIES", 2 * _session_max_entries),
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE}


@app.get("/readyz")
def readyz() -> JSONResponse:
    try:
        _upstream.ready()
    except UpstreamError as exc:
        log.warning("readiness probe found unusable upstream", extra={"error": str(exc)})
        return JSONResponse({"status": "unready", "suite": _upstream.suite}, status_code=503)
    return JSONResponse({"status": "ready", "sessions": len(_sessions), "suite": _upstream.suite})


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
        _sessions.ensure_unused(request.session_id)
        downstream = _legacy_server.accept(request)
    except FrameError as exc:
        metrics.record_handshake(SERVICE, str(body.get("suite", "unknown")), "rejected")
        log.warning("rejected device handshake", extra={"error": str(exc)})
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except pqcnode.SessionAlreadyUsed as exc:
        metrics.record_handshake(SERVICE, str(body.get("suite", "unknown")), "replayed")
        log.warning(
            "rejected reused session identifier",
            extra={"session_id": str(body.get("session_id", "unknown"))},
        )
        raise HTTPException(status_code=409, detail="session identifier was already used") from exc
    except pqcnode.SessionHistoryFull as exc:
        metrics.record_handshake(SERVICE, str(body.get("suite", "unknown")), "capacity")
        log.warning("session identifier history capacity exhausted")
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        upstream_id, upstream = _upstream.open_session()
    except UpstreamError as exc:
        metrics.record_handshake(SERVICE, _upstream.suite, "upstream_failed")
        log.error("upstream handshake failed", extra={"error": str(exc)})
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    try:
        _sessions.put(request.session_id, (downstream, upstream))
    except pqcnode.SessionAlreadyUsed as exc:
        metrics.record_handshake(SERVICE, request.suite, "replayed")
        log.warning("rejected reused session identifier", extra={"session_id": request.session_id})
        raise HTTPException(status_code=409, detail="session identifier was already used") from exc
    except pqcnode.SessionHistoryFull as exc:
        metrics.record_handshake(SERVICE, request.suite, "capacity")
        log.warning("session identifier history capacity exhausted")
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    metrics.record_handshake(SERVICE, request.suite, "established")
    metrics.record_handshake(SERVICE, _upstream.suite, "established")
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
    except cs.RecordSessionExhausted as exc:
        _sessions.drop(frame.session_id)
        metrics.record_frame(SERVICE, frame.suite, "session_exhausted")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
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
    except FrameError as exc:
        _sessions.drop(frame.session_id)
        metrics.record_frame(SERVICE, _upstream.suite, "session_exhausted")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except UpstreamSessionRejected as exc:
        _sessions.drop(frame.session_id)
        metrics.record_frame(SERVICE, _upstream.suite, "session_exhausted")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
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
