"""Simulated legacy weather device.

Replays the daily records in data/weather_data.csv to the gateway, one reading
at a time, at REPLAY_INTERVAL_SECONDS. Uses classical crypto only and is treated
as non-upgradeable firmware -- this service does not change during the migration.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx

from ..common import cryptoutil as cu
from ..common.config import (
    DEFAULT_MAX_RECORDS_PER_SESSION,
    DEFAULT_SESSION_TTL_SECONDS,
    env_bool,
    env_float,
    env_int,
    env_str,
    setup_logging,
)
from ..common.handshake import HandshakeError
from ..common.sessions import iso, utc_now
from ..common.weather import iter_readings, parse_weather_file
from .gateway_client import GatewayClient

log = setup_logging("device")


def wait_for_gateway(base_url: str, attempts: int, delay: float) -> bool:
    """Compose starts us alongside the gateway; give it a moment to bind."""
    url = f"{base_url.rstrip('/')}/health"
    for attempt in range(1, attempts + 1):
        try:
            if httpx.get(url, timeout=3.0).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        log.info("waiting for gateway (%d/%d)", attempt, attempts)
        time.sleep(delay)
    return False


def main() -> int:
    device_id = env_str("DEVICE_ID", "device-berlin-01")
    gateway_url = env_str("GATEWAY_URL", "http://gateway:8000")
    keys_dir = Path(env_str("KEYS_DIR", "keys"))
    data_file = env_str("DATA_FILE", "data/weather_data.csv")
    interval = env_float("REPLAY_INTERVAL_SECONDS", 2.0)
    loop_forever = env_bool("LOOP_FOREVER", True)
    max_records = env_int("MAX_RECORDS", 0)  # 0 = no limit

    station, readings = parse_weather_file(data_file)
    log.info(
        "loaded %d readings (%s .. %s) for station %.4f,%.4f (%s)",
        len(readings), readings[0].date, readings[-1].date,
        station.lat, station.lon, station.tz,
    )

    if not wait_for_gateway(gateway_url, attempts=30, delay=2.0):
        log.error("gateway never became healthy at %s", gateway_url)
        return 1

    client = GatewayClient(
        base_url=gateway_url,
        device_id=device_id,
        device_static_key=cu.load_private_key(keys_dir / "device_ecdh_priv.pem"),
        gateway_public_key=cu.load_public_key(keys_dir / "gateway_ecdh_pub.pem"),
        log=log,
    )

    sent = accepted = failed = 0
    log.info(
        "replaying every %.2fs (loop=%s, suite=ECDH-P256-static-static+AES-256-GCM)",
        interval, loop_forever,
    )

    try:
        for reading in iter_readings(readings, loop=loop_forever):
            payload = {
                "device_id": device_id,
                "station": station.to_dict(),
                "sent_at": iso(utc_now()),
                **reading.to_dict(),
            }

            try:
                result = client.send_reading(payload)
                sent += 1
                if result.get("status") == "accepted":
                    accepted += 1
                    log.info("sent date=%s (accepted, cloud=%s)",
                             reading.date, result.get("cloud"))
                else:
                    failed += 1
                    log.warning("sent date=%s rejected: %s",
                                reading.date, result.get("reason"))
            except (HandshakeError, httpx.HTTPError) as exc:
                # Legacy behaviour: log, drop the reading, keep going. No queue,
                # no retry budget, no backoff. Known availability weakness.
                failed += 1
                log.error("send failed date=%s: %s", reading.date, exc)

            if max_records and sent >= max_records:
                log.info("reached MAX_RECORDS=%d, stopping", max_records)
                break

            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        client.close()
        log.info("totals sent=%d accepted=%d failed=%d", sent, accepted, failed)

    return 0


if __name__ == "__main__":
    sys.exit(main())
