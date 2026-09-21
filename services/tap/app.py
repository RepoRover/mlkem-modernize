"""Passive wiretap.

Models an adversary with access to the public network: it forwards every
request unchanged and writes a copy to a capture file. It never modifies,
delays, or drops traffic, so the system behaves identically whether or not it
is present -- which is the point. A passive observer is the weakest realistic
attacker, and the legacy suite already loses to it once RSA falls.

The capture is a JSON Lines file so the offline harvester can replay it without
needing a packet parser.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response

import pqcnode
from pqcnode.config import env_float, env_path, env_str

SERVICE = "tap"

log = pqcnode.configure(SERVICE, env_str("LOG_LEVEL", "INFO"))

app = FastAPI(title="Passive Network Tap", version="0.1.0")

_link = env_str("LINK_LABEL", "unknown")
_upstream = env_str("TAP_UPSTREAM_URL", "http://gateway:8080").rstrip("/")
_capture_path = env_path("CAPTURE_PATH", f"run/capture/{_link}.jsonl")
_client = httpx.Client(timeout=env_float("UPSTREAM_TIMEOUT_SECONDS", 10.0))
_write_lock = threading.Lock()
_captured = 0
_capture_errors = 0

_capture_path.parent.mkdir(parents=True, exist_ok=True)


def _record(entry: dict[str, Any]) -> None:
    """Append one observation to the capture file.

    Recording failures are swallowed deliberately. A wiretap that breaks the
    link it observes is not passive, and an attacker whose disk filled up would
    not take the victim's network down with it. Losing an observation is the
    correct failure mode here; losing the traffic is not.
    """
    global _captured, _capture_errors
    line = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    try:
        with _write_lock:
            with _capture_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
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
        "capture_errors": _capture_errors,
        "capture_path": str(_capture_path),
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def relay(path: str, request: Request) -> Response:
    body = await request.body()
    url = f"{_upstream}/{path}"

    parsed: Any = None
    if body:
        try:
            parsed = json.loads(body)
        except ValueError:
            # Not every body is JSON -- the public-key endpoint returns PEM.
            parsed = None

    upstream = _client.request(
        request.method,
        url,
        content=body or None,
        params=dict(request.query_params),
        headers={"Content-Type": request.headers.get("content-type", "application/json")},
    )

    _record(
        {
            "ts": time.time(),
            "link": _link,
            "method": request.method,
            "path": "/" + path,
            "status": upstream.status_code,
            "request_json": parsed,
            "request_raw": None if parsed is not None else _safe_text(body),
            "response_raw": _safe_text(upstream.content),
        }
    )

    log.info(
        "frame observed",
        extra={"link": _link, "path": "/" + path, "status": upstream.status_code},
    )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type"),
    )


def _safe_text(raw: bytes, limit: int = 8192) -> str | None:
    if not raw:
        return None
    try:
        return raw[:limit].decode("utf-8")
    except UnicodeDecodeError:
        return raw[:limit].hex()
