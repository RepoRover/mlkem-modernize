"""Simulated legacy weather station.

The device stands in for fielded firmware that cannot be updated. It talks to
the gateway with :mod:`urllib.request` rather than a modern HTTP client,
keeping its dependency surface to the standard library plus one ageing crypto
package -- which is why it cannot perform ML-KEM itself and must delegate the
post-quantum link to the gateway.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pqcnode
import pqcsuite as cs
from pqcnode.config import env_bool, env_float, env_int, env_path, env_str
from pqcwire.telemetry import WeatherReading, load_dataset

SERVICE = "legacy-device"

log = pqcnode.configure(SERVICE, env_str("LOG_LEVEL", "INFO"))


class DeviceConfig:
    def __init__(self) -> None:
        self.gateway_url = env_str("GATEWAY_URL", "http://gateway:8080").rstrip("/")
        self.device_id = env_str("DEVICE_ID", "weather-station-01")
        self.dataset_path = env_path("DATASET_PATH", "data/weather_data.csv")
        self.interval = env_float("SEND_INTERVAL_SECONDS", 1.0)
        self.max_readings = env_int("MAX_READINGS", 0)
        self.loop_forever = env_bool("LOOP_FOREVER", False)
        self.timeout = env_float("HTTP_TIMEOUT_SECONDS", 10.0)
        self.startup_retries = env_int("STARTUP_RETRIES", 30)


def _get(url: str, timeout: float) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
        return bytes(response.read())


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        raw = response.read().decode("utf-8")
    return dict(json.loads(raw)) if raw else {}


def _wait_for_gateway(config: DeviceConfig) -> bytes:
    """Poll for the gateway's public key until it is reachable.

    Containers start in an arbitrary order, so treating a cold gateway as fatal
    would make the stack's health depend on scheduling luck.
    """
    delay = 0.5
    last_error: Exception | None = None
    for attempt in range(1, config.startup_retries + 1):
        try:
            return _get(f"{config.gateway_url}/legacy/pubkey", config.timeout)
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
            log.info(
                "gateway not ready, retrying",
                extra={"attempt": attempt, "delay_seconds": round(delay, 2)},
            )
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)
    raise RuntimeError(f"gateway unreachable after {config.startup_retries} attempts: {last_error}")


def _report_capabilities() -> None:
    report = cs.probe()
    log.info(
        "device capability report",
        extra={
            "python_version": report.python_version,
            "cryptography_version": report.cryptography_version,
            "mlkem_available": report.mlkem_available,
            "supported_suites": report.supported_suites,
            "reason": report.reason,
        },
    )
    if not report.mlkem_available:
        log.warning(
            "device cannot perform post-quantum key establishment; "
            "the gateway must broker it on the device's behalf",
            extra={"reason": report.reason},
        )


def run(config: DeviceConfig | None = None) -> int:
    config = config or DeviceConfig()
    _report_capabilities()

    dataset = load_dataset(Path(config.dataset_path))
    log.info(
        "dataset loaded",
        extra={"readings": len(dataset), "station": dataset.station.to_dict()},
    )

    pem = _wait_for_gateway(config)
    client = cs.LegacyClient(cs.load_public_key(pem))
    request, session = client.open_session()
    _post_json(f"{config.gateway_url}/legacy/session", request.to_dict(), config.timeout)
    log.info(
        "session established with gateway",
        extra={"session_id": request.session_id, "suite": request.suite},
    )

    sent = 0
    limit = config.max_readings or None
    while True:
        for reading in dataset:
            if limit is not None and sent >= limit:
                log.info("reading limit reached", extra={"sent": sent})
                return sent
            _send(config, session, reading)
            sent += 1
            if config.interval > 0:
                time.sleep(config.interval)
        if not config.loop_forever:
            log.info("dataset exhausted", extra={"sent": sent})
            return sent


def _send(config: DeviceConfig, session: cs.RecordSession, reading: WeatherReading) -> None:
    frame = session.seal(reading.to_json().encode("utf-8"))
    try:
        _post_json(f"{config.gateway_url}/legacy/frames", frame.to_dict(), config.timeout)
    except urllib.error.HTTPError as exc:
        log.error(
            "gateway rejected frame",
            extra={"seq": frame.seq, "status": exc.code, "date": reading.date},
        )
        return
    except (urllib.error.URLError, OSError) as exc:
        log.error("gateway unreachable", extra={"seq": frame.seq, "error": str(exc)})
        return
    log.info(
        "reading sent",
        extra={
            "seq": frame.seq,
            "date": reading.date,
            "suite": frame.suite,
            "session_id": frame.session_id,
        },
    )
