"""Environment-variable configuration helpers.

Configuration is read once at startup and failures are loud: a node that
cannot parse its own settings should refuse to start rather than fall back to
a default that silently weakens its security posture.
"""

from __future__ import annotations

import os
from pathlib import Path

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


class ConfigError(RuntimeError):
    """Raised when an environment variable is missing or unparseable."""


def env_str(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise ConfigError(f"required environment variable {name} is not set")
    return value


def env_int(name: str, default: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None:
        if default is None:
            raise ConfigError(f"required environment variable {name} is not set")
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not an integer") from None


def env_float(name: str, default: float | None = None) -> float:
    raw = os.environ.get(name)
    if raw is None:
        if default is None:
            raise ConfigError(f"required environment variable {name} is not set")
        return default
    try:
        return float(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not a number") from None


def env_bool(name: str, default: bool | None = None) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        if default is None:
            raise ConfigError(f"required environment variable {name} is not set")
        return default
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ConfigError(f"{name}={raw!r} is not a boolean")


def env_path(name: str, default: str | None = None) -> Path:
    return Path(env_str(name, default))
