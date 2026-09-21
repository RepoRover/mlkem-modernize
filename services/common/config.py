"""Environment-driven configuration and logging setup.

Kept deliberately plain: os.environ with typed getters, no settings framework.
"""

from __future__ import annotations

import logging
import os
import sys
import time

DEFAULT_MAX_RECORDS_PER_SESSION = 100
DEFAULT_SESSION_TTL_SECONDS = 600


def env_str(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"required environment variable {name} is not set")
    return value


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number, got {raw!r}") from exc


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def setup_logging(service: str) -> logging.Logger:
    """Basic line logging to stdout.

    Baseline only -- no structured logging, no correlation ids, no shipping.
    That gap is on the weakness list and is picked up by the observability work.

    Never log key material, shared secrets or decrypted payloads. Session ids and
    sequence numbers are fine and are what we use to trace a message.
    """
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()

    # Log in UTC so timestamps line up with the ISO 8601 fields on the wire
    # (expires_at, received_at). Mixing local and UTC makes traces unreadable.
    logging.Formatter.converter = time.gmtime

    logging.basicConfig(
        level=getattr(logging, level_name, logging.INFO),
        format="%(asctime)sZ %(levelname)-7s [" + service + "] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
        force=True,
    )

    # httpx logs every request at INFO, which drowns out our own lines.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    return logging.getLogger(service)
