"""Structured JSON Lines logging for the Gateway process."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import cast

type JsonValue = None | str | int | float | bool | list[str]

_SAFE_FIELDS = frozenset(
    {
        "attempt",
        "device_id",
        "error",
        "errors",
        "event",
        "key_id",
        "kem_key_id",
        "observation_id",
        "result",
    }
)


def _json_value(value: object) -> JsonValue:
    """Return a JSON-compatible representation without introspecting objects."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list | tuple):
        items = cast(list[object] | tuple[object, ...], value)
        return [str(item) for item in items]
    return str(value)


class JsonLineFormatter(logging.Formatter):
    """Format one log record as one JSON object."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "service": self._service,
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        trace_id = getattr(record, "otelTraceID", None)
        span_id = getattr(record, "otelSpanID", None)
        if trace_id not in (None, "0", 0):
            payload["trace_id"] = str(trace_id)
        if span_id not in (None, "0", 0):
            payload["span_id"] = str(span_id)
        for key in _SAFE_FIELDS:
            if key in record.__dict__:
                payload[key] = _json_value(record.__dict__[key])
        return json.dumps(payload, ensure_ascii=True)


def configure_json_logging(service: str) -> None:
    """Add JSONL stdout logging while preserving an OpenTelemetry handler."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    formatter = JsonLineFormatter(service)
    stream_configured = False
    for handler in root.handlers:
        if handler.__class__.__module__.startswith("opentelemetry."):
            handler.setFormatter(formatter)
        elif isinstance(handler, logging.StreamHandler):
            handler.setFormatter(formatter)
            handler._mlkem_json_handler = True  # type: ignore[attr-defined]
            stream_configured = True
    if not stream_configured:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        handler._mlkem_json_handler = True  # type: ignore[attr-defined]
        root.addHandler(handler)
