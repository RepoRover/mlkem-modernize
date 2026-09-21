"""Configuration parsing and the device's startup helpers.

Misreading an env var is a silent production failure -- REPLAY_INTERVAL_SECONDS
falling back to a default because someone wrote "2s" would look like the system
working, just slowly. These getters must fail loudly instead.
"""

from __future__ import annotations

import logging

import httpx
import pytest

from services.common.config import (
    DEFAULT_MAX_RECORDS_PER_SESSION,
    DEFAULT_SESSION_TTL_SECONDS,
    env_bool,
    env_float,
    env_int,
    env_str,
    setup_logging,
)

# ------------------------------------------------------------------- env_str


def test_env_str_reads_and_defaults(monkeypatch):
    monkeypatch.setenv("WX_TEST_STR", "hello")
    assert env_str("WX_TEST_STR") == "hello"
    monkeypatch.delenv("WX_TEST_STR", raising=False)
    assert env_str("WX_TEST_STR", "fallback") == "fallback"


def test_env_str_without_a_default_is_fatal(monkeypatch):
    """A missing required setting must stop the service, not run half-configured."""
    monkeypatch.delenv("WX_TEST_MISSING", raising=False)
    with pytest.raises(RuntimeError, match="WX_TEST_MISSING"):
        env_str("WX_TEST_MISSING")


# ------------------------------------------------------------------- env_int


@pytest.mark.parametrize("raw, expected", [("42", 42), ("0", 0), ("-7", -7), (" 5 ", 5)])
def test_env_int_parses(monkeypatch, raw, expected):
    monkeypatch.setenv("WX_TEST_INT", raw)
    assert env_int("WX_TEST_INT", 99) == expected


@pytest.mark.parametrize("raw", ["", "   "])
def test_env_int_treats_blank_as_unset(monkeypatch, raw):
    """An empty compose variable must mean 'default', not a crash."""
    monkeypatch.setenv("WX_TEST_INT", raw)
    assert env_int("WX_TEST_INT", 99) == 99


@pytest.mark.parametrize("raw", ["abc", "1.5", "100records", "1e3"])
def test_env_int_rejects_garbage(monkeypatch, raw):
    monkeypatch.setenv("WX_TEST_INT", raw)
    with pytest.raises(RuntimeError, match="must be an integer"):
        env_int("WX_TEST_INT", 99)


# ----------------------------------------------------------------- env_float


@pytest.mark.parametrize("raw, expected", [("2.0", 2.0), ("0.05", 0.05), ("3", 3.0)])
def test_env_float_parses(monkeypatch, raw, expected):
    monkeypatch.setenv("WX_TEST_FLOAT", raw)
    assert env_float("WX_TEST_FLOAT", 1.0) == pytest.approx(expected)


def test_env_float_blank_is_default(monkeypatch):
    monkeypatch.setenv("WX_TEST_FLOAT", "")
    assert env_float("WX_TEST_FLOAT", 2.0) == pytest.approx(2.0)


@pytest.mark.parametrize("raw", ["fast", "2s", "0.05ms"])
def test_env_float_rejects_garbage(monkeypatch, raw):
    monkeypatch.setenv("WX_TEST_FLOAT", raw)
    with pytest.raises(RuntimeError, match="must be a number"):
        env_float("WX_TEST_FLOAT", 1.0)


# ------------------------------------------------------------------ env_bool


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "Yes", "on", " true "])
def test_env_bool_truthy(monkeypatch, raw):
    monkeypatch.setenv("WX_TEST_BOOL", raw)
    assert env_bool("WX_TEST_BOOL", False) is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "no", "off", "anything else"])
def test_env_bool_falsy(monkeypatch, raw):
    monkeypatch.setenv("WX_TEST_BOOL", raw)
    assert env_bool("WX_TEST_BOOL", True) is False


def test_env_bool_blank_is_default(monkeypatch):
    monkeypatch.setenv("WX_TEST_BOOL", "")
    assert env_bool("WX_TEST_BOOL", True) is True
    monkeypatch.delenv("WX_TEST_BOOL", raising=False)
    assert env_bool("WX_TEST_BOOL", False) is False


# ------------------------------------------------------------------- logging


def test_setup_logging_returns_a_named_logger_and_honours_level(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    log = setup_logging("unit-test-service")

    assert log.name == "unit-test-service"
    assert logging.getLogger().level == logging.WARNING


def test_setup_logging_falls_back_on_a_bogus_level(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "NOT_A_LEVEL")
    setup_logging("unit-test-service")
    assert logging.getLogger().level == logging.INFO


def test_httpx_logger_is_quietened(monkeypatch):
    """httpx logs every request at INFO and would bury our own lines."""
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    setup_logging("unit-test-service")
    assert logging.getLogger("httpx").level == logging.WARNING


def test_defaults_are_the_documented_ones():
    """These appear in ARCHITECTURE.md and docker-compose.yml; keep them in step."""
    assert DEFAULT_MAX_RECORDS_PER_SESSION == 100
    assert DEFAULT_SESSION_TTL_SECONDS == 600


# ------------------------------------------------- device startup behaviour


def test_wait_for_gateway_returns_true_once_healthy(monkeypatch):
    from services.device import main as device_main

    calls = {"n": 0}

    class Response:
        status_code = 200

    def fake_get(url, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("not up yet")
        return Response()

    monkeypatch.setattr(device_main.httpx, "get", fake_get)
    monkeypatch.setattr(device_main.time, "sleep", lambda _: None)

    assert device_main.wait_for_gateway("http://gateway:8000", attempts=10, delay=0) is True
    assert calls["n"] == 3


def test_wait_for_gateway_gives_up_and_reports_failure(monkeypatch):
    """The device must exit non-zero rather than spin forever."""
    from services.device import main as device_main

    def always_fails(url, timeout):
        raise httpx.ConnectError("never comes up")

    monkeypatch.setattr(device_main.httpx, "get", always_fails)
    monkeypatch.setattr(device_main.time, "sleep", lambda _: None)

    assert device_main.wait_for_gateway("http://gateway:8000", attempts=3, delay=0) is False


def test_wait_for_gateway_ignores_a_non_200(monkeypatch):
    from services.device import main as device_main

    class Response:
        status_code = 503

    monkeypatch.setattr(device_main.httpx, "get", lambda url, timeout: Response())
    monkeypatch.setattr(device_main.time, "sleep", lambda _: None)

    assert device_main.wait_for_gateway("http://gateway:8000", attempts=2, delay=0) is False
