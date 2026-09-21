"""Legacy Device process entry point."""

import asyncio
import logging
import ssl

import httpx
from pydantic import ValidationError

from device.config import Settings
from device.dataset import load_dataset, observations_for_cycle
from device.delivery import deliver
from device.errors import DeviceError, validation_codes

logger = logging.getLogger("device")


async def run(settings: Settings) -> None:
    """Load Device inputs and run the configured calendar cycles."""
    try:
        key = settings.device_key_file.read_bytes()
    except OSError as error:
        raise DeviceError("Device AES key could not be read") from error
    if len(key) != 32:
        raise DeviceError("Device AES key must be exactly 32 bytes")

    location, sources = load_dataset(settings.weather_csv_file)
    try:
        tls = ssl.create_default_context(cafile=str(settings.ca_cert_file))
    except (OSError, ssl.SSLError) as error:
        raise DeviceError("Gateway CA certificate could not be loaded") from error
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.maximum_version = ssl.TLSVersion.TLSv1_2

    logger.info(
        "event=settings_keys_loaded device_id=%s key_id=%s rows=%d",
        settings.device_id,
        settings.device_key_id,
        len(sources),
    )
    logger.info("event=service_ready")
    async with httpx.AsyncClient(
        verify=tls, follow_redirects=False, timeout=None
    ) as client:
        cycle = 0
        while settings.max_cycles is None or cycle < settings.max_cycles:
            for observation in observations_for_cycle(
                settings.device_id, location, sources, cycle
            ):
                accepted = await deliver(client, settings, key, observation)
                if accepted:
                    await asyncio.sleep(settings.send_interval_seconds)
            cycle += 1


def main() -> None:
    """Run the Device command-line process from environment configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s service=device level=%(levelname)s %(message)s",
    )
    try:
        settings = Settings.from_environment()
    except ValidationError as error:
        logger.error("event=settings_rejected errors=%s", validation_codes(error))
        raise SystemExit(1) from None

    try:
        asyncio.run(run(settings))
    except KeyboardInterrupt:
        logger.info("event=service_stopping result=interrupted")
    except DeviceError as error:
        logger.error("event=fatal error=%s", error)
        raise SystemExit(1) from None
    except Exception:  # noqa: BLE001 - never expose an unexpected exception value
        logger.error("event=fatal error=internal")
        raise SystemExit(1) from None
    else:
        logger.info("event=service_stopping result=complete")


if __name__ == "__main__":
    main()
