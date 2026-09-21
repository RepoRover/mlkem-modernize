"""Structured JSON logging.

Every node emits one JSON object per line so that a log aggregator can filter
on the cipher suite in use. That field is what turns "is anything still
speaking a quantum-vulnerable suite?" into a query rather than an audit.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

_RESERVED = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()) | {
    "message",
    "asctime",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "service": self._service,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, sort_keys=True)


def configure(service: str, level: str = "INFO") -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))

    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    return logging.getLogger(service)


def bind(logger: logging.Logger, **fields: Any) -> logging.LoggerAdapter:
    """Attach fields that should appear on every record from this adapter."""

    class _Adapter(logging.LoggerAdapter):
        def process(self, msg: str, kwargs: dict[str, Any]) -> Any:
            extra = dict(self.extra or {})
            extra.update(kwargs.get("extra") or {})
            kwargs["extra"] = extra
            return msg, kwargs

    return _Adapter(logger, fields)


def correlation_id(prefix: str = "req", value: str | None = None) -> str:
    import os

    return value or f"{prefix}-{os.urandom(6).hex()}"
