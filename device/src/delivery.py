"""Gateway delivery and retry behavior."""

import asyncio
import json
import logging
import math
import random
import ssl
from enum import StrEnum
from typing import Any

import httpx
from config import Settings
from crypto import encrypt_observation
from errors import DeviceError
from models import Observation

logger = logging.getLogger("device")


class DeliveryAction(StrEnum):
    """How Device handles a Gateway response."""

    ACCEPT = "accept"
    SKIP = "skip"
    RETRY = "retry"
    FATAL = "fatal"


def classify_response(
    status_code: int, body: Any, observation_id: str
) -> DeliveryAction:
    """Classify one Gateway response according to the retry contract."""
    if status_code in (200, 201):
        if (
            isinstance(body, dict)
            and body.get("observation_id") == observation_id
            and body.get("status") in ("stored", "duplicate")
        ):
            return DeliveryAction.ACCEPT
        return DeliveryAction.FATAL
    if status_code in (408, 429) or status_code >= 500:
        if (
            status_code == 502
            and isinstance(body, dict)
            and body.get("status") == "upstream_rejected"
        ):
            return DeliveryAction.FATAL
        return DeliveryAction.RETRY
    if status_code in (401, 403):
        return DeliveryAction.FATAL
    if 400 <= status_code < 500:
        return DeliveryAction.SKIP
    return DeliveryAction.FATAL


def retry_delay(
    initial: float, maximum: float, retry: int, sample: float | None = None
) -> float:
    """Return capped exponential backoff with bounded equal jitter."""
    try:
        cap = min(maximum, math.ldexp(initial, retry - 1))
    except OverflowError:
        cap = maximum
    return cap * (0.5 + 0.5 * (random.random() if sample is None else sample))


def _certificate_error(error: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if isinstance(current, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


async def deliver(
    client: httpx.AsyncClient,
    settings: Settings,
    key: bytes,
    observation: Observation,
) -> bool:
    """Deliver one observation, retrying transient failures indefinitely."""
    retry = 0
    while True:
        body: Any = None
        envelope = encrypt_observation(observation, settings.device_key_id, key)
        try:
            async with asyncio.timeout(settings.gateway_timeout_seconds):
                response = await client.post(
                    str(settings.gateway_url), json=envelope.model_dump()
                )
            try:
                body = response.json()
            except json.JSONDecodeError, UnicodeDecodeError:
                body = None
            action = classify_response(
                response.status_code, body, observation.observation_id
            )
        except (httpx.RequestError, TimeoutError) as error:
            if _certificate_error(error):
                raise DeviceError("Gateway certificate verification failed") from error
            action = DeliveryAction.RETRY

        if action is DeliveryAction.ACCEPT:
            logger.info(
                "event=observation_accepted observation_id=%s result=%s",
                observation.observation_id,
                body.get("status") if isinstance(body, dict) else "accepted",
            )
            return True
        if action is DeliveryAction.SKIP:
            logger.warning(
                "event=observation_rejected observation_id=%s result=permanent",
                observation.observation_id,
            )
            return False
        if action is DeliveryAction.FATAL:
            raise DeviceError(
                "Gateway returned a fatal authentication or protocol error"
            )

        retry += 1
        delay = retry_delay(
            settings.retry_initial_seconds, settings.retry_max_seconds, retry
        )
        logger.warning(
            "event=delivery_retry observation_id=%s attempt=%d delay_seconds=%.3f",
            observation.observation_id,
            retry,
            delay,
        )
        await asyncio.sleep(delay)
