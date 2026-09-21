"""Bounded teaching wiretap that relays and records application traffic.

Normal protocol traffic is forwarded unchanged. Explicit byte, time, encoding,
and capture-storage ceilings keep the in-path observer from becoming an
unbounded proxy. Capture failure or a full capture budget never interrupts
otherwise valid relayed traffic.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response

import pqcnode
from pqcnode.config import env_float, env_int, env_path, env_str

SERVICE = "tap"

log = pqcnode.configure(SERVICE, env_str("LOG_LEVEL", "INFO"))

app = FastAPI(title="Bounded Passive Network Tap", version="0.2.0")

_link = env_str("LINK_LABEL", "unknown")
_upstream = env_str("TAP_UPSTREAM_URL", "http://gateway:8080").rstrip("/")
_capture_path = env_path("CAPTURE_PATH", f"run/capture/{_link}.jsonl")
_timeout = env_float("UPSTREAM_TIMEOUT_SECONDS", 10.0)
_deadline = env_float("RELAY_DEADLINE_SECONDS", 15.0)
_max_request_bytes = env_int("MAX_REQUEST_BYTES", 65536)
_max_response_bytes = env_int("MAX_RESPONSE_BYTES", 65536)
_capture_field_bytes = env_int("CAPTURE_FIELD_BYTES", 32768)
_capture_max_bytes = env_int("CAPTURE_MAX_BYTES", 16 * 1024 * 1024)
if (
    _timeout <= 0
    or _deadline <= 0
    or min(
        _max_request_bytes,
        _max_response_bytes,
        _capture_field_bytes,
        _capture_max_bytes,
    )
    < 1
):
    raise pqcnode.ConfigError("tap timeout, deadline, and byte limits must be positive")

_client = httpx.AsyncClient(timeout=_timeout)
_write_lock = threading.Lock()
_captured = 0
_capture_errors = 0
_capture_dropped = 0

_capture_path.parent.mkdir(parents=True, exist_ok=True)
try:
    _capture_bytes = _capture_path.stat().st_size
except OSError:
    _capture_bytes = 0


def _record(entry: dict[str, Any]) -> None:
    """Append within the capture budget; storage exhaustion never breaks relay."""
    global _captured, _capture_bytes, _capture_dropped, _capture_errors
    encoded = (json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n").encode()
    try:
        with _write_lock:
            if _capture_bytes + len(encoded) > _capture_max_bytes:
                _capture_dropped += 1
                return
            with _capture_path.open("ab") as handle:
                handle.write(encoded)
            _capture_bytes += len(encoded)
            _captured += 1
    except OSError as exc:
        _capture_errors += 1
        log.error(
            "capture write failed; traffic still relayed",
            extra={"link": _link, "error": str(exc), "capture_errors": _capture_errors},
        )


@app.get("/tap/healthz")
def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": SERVICE,
        "link": _link,
        "captured": _captured,
        "capture_bytes": _capture_bytes,
        "capture_dropped": _capture_dropped,
        "capture_errors": _capture_errors,
        "capture_path": str(_capture_path),
    }


async def _request_body(request: Request, deadline_seconds: float) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_bytes = int(declared)
            if declared_bytes < 0 or declared_bytes > _max_request_bytes:
                raise ValueError("request body exceeds tap limit")
        except ValueError as exc:
            raise ValueError("invalid or oversized request content-length") from exc

    body = bytearray()
    async with asyncio.timeout(deadline_seconds):
        async for chunk in request.stream():
            if len(body) + len(chunk) > _max_request_bytes:
                raise ValueError("request body exceeds tap limit")
            body.extend(chunk)
    return bytes(body)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def relay(path: str, request: Request) -> Response:
    started = time.monotonic()
    try:
        body = await _request_body(request, _deadline)
    except ValueError as exc:
        return Response(content=str(exc), status_code=413, media_type="text/plain")
    except TimeoutError:
        return Response(content="request body deadline expired", status_code=408)

    url = f"{_upstream}/{path}"
    remaining = _deadline - (time.monotonic() - started)
    if remaining <= 0:
        return Response(content="relay deadline expired", status_code=502)
    try:
        async with asyncio.timeout(remaining):
            async with _client.stream(
                request.method,
                url,
                content=body or None,
                params=dict(request.query_params),
                headers={
                    "Content-Type": request.headers.get("content-type", "application/json"),
                    "Accept-Encoding": "identity",
                },
            ) as upstream:
                if upstream.headers.get("content-encoding", "identity").lower() != "identity":
                    return Response(
                        content="compressed upstream responses are unsupported",
                        status_code=502,
                    )
                declared = upstream.headers.get("content-length")
                if declared is not None and int(declared) > _max_response_bytes:
                    return Response(content="upstream response exceeds tap limit", status_code=502)
                response_body = bytearray()
                async for chunk in upstream.aiter_bytes():
                    if len(response_body) + len(chunk) > _max_response_bytes:
                        return Response(
                            content="upstream response exceeds tap limit", status_code=502
                        )
                    response_body.extend(chunk)
                status_code = upstream.status_code
                content_type = upstream.headers.get("content-type")
    except (httpx.HTTPError, TimeoutError, ValueError) as exc:
        log.warning("bounded relay failed", extra={"link": _link, "error": str(exc)})
        return Response(content="upstream relay failed", status_code=502)

    parsed: Any = None
    if body and len(body) <= _capture_field_bytes:
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None

    _record(
        {
            "ts": time.time(),
            "link": _link,
            "method": request.method,
            "path": "/" + path,
            "status": status_code,
            "request_json": parsed,
            "request_raw": (
                None if parsed is not None else _safe_text(body, limit=_capture_field_bytes)
            ),
            "response_raw": _safe_text(bytes(response_body), limit=_capture_field_bytes),
        }
    )

    log.info(
        "frame observed",
        extra={"link": _link, "path": "/" + path, "status": status_code},
    )
    return Response(
        content=bytes(response_body),
        status_code=status_code,
        media_type=content_type,
    )


def _safe_text(raw: bytes, limit: int = 8192) -> str | None:
    if not raw:
        return None
    clipped = raw[:limit]
    suffix = "...[truncated]" if len(raw) > limit else ""
    try:
        return clipped.decode("utf-8") + suffix
    except UnicodeDecodeError:
        return clipped.hex() + suffix
