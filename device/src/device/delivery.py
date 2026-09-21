"""Gateway delivery and retry behavior."""

import asyncio
import json
import logging
import math
import random
import ssl
from enum import StrEnum

import httpx
from opentelemetry import trace

from device.config import Settings
from device.crypto import encrypt_observation
from device.errors import DeviceError
from device.models import Observation

logger = logging.getLogger("device")
tracer = trace.get_tracer("device.delivery")
MAX_GATEWAY_RESPONSE_BYTES = 32 * 1024


class DeliveryAction(StrEnum):
    """How Device handles a Gateway response."""

    ACCEPT = "accept"
    SKIP = "skip"
    RETRY = "retry"
    FATAL = "fatal"


def response_status(body: object) -> str | None:
    """Extract a string status only from a JSON object with the expected field."""
    match body:
        case {"status": str() as status}:
            return status
        case _:
            return None


def classify_response(
    status_code: int, body: object, observation_id: str
) -> DeliveryAction:
    """Classify one Gateway response according to the retry contract."""
    if status_code in (200, 201):
        match body:
            case {
                "observation_id": str() as response_id,
                "status": "stored" | "duplicate",
            } if response_id == observation_id:
                return DeliveryAction.ACCEPT
            case _:
                return DeliveryAction.FATAL
    if status_code in (408, 429) or status_code >= 500:
        if status_code == 502 and response_status(body) == "upstream_rejected":
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
    """Deliver one observation in a trace, retrying transient failures."""
    with tracer.start_as_current_span(
        "device.deliver",
        attributes={"observation.id": observation.observation_id},
    ) as span:
        accepted = await _deliver_with_retries(client, settings, key, observation)
        span.set_attribute("observation.result", "accepted" if accepted else "rejected")
        return accepted


async def _deliver_with_retries(
    client: httpx.AsyncClient,
    settings: Settings,
    key: bytes,
    observation: Observation,
) -> bool:
    """Implement bounded-response delivery under the parent delivery span."""
    retry = 0
    while True:
        body: object = None
        with tracer.start_as_current_span(
            "device.encrypt",
            attributes={"crypto.algorithm": "AES-256-GCM"},
        ):
            envelope = encrypt_observation(observation, settings.device_key_id, key)
        try:
            async with asyncio.timeout(settings.gateway_timeout_seconds):
                async with client.stream(
                    "POST",
                    str(settings.gateway_url),
                    json=envelope.model_dump(),
                    headers={"Accept-Encoding": "identity"},
                ) as response:
                    if (
                        response.headers.get("content-encoding", "identity").lower()
                        != "identity"
                    ):
                        raise DeviceError(
                            "Compressed Gateway responses are unsupported"
                        )
                    content = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        if len(content) + len(chunk) > MAX_GATEWAY_RESPONSE_BYTES:
                            raise DeviceError("Gateway response is too large")
                        content.extend(chunk)
            try:
                body = json.loads(content)
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
            result = response_status(body)
            logger.info(
                "event=observation_accepted observation_id=%s result=%s",
                observation.observation_id,
                result,
                extra={
                    "event": "observation_accepted",
                    "observation_id": observation.observation_id,
                    "result": result,
                },
            )
            return True
        if action is DeliveryAction.SKIP:
            logger.warning(
                "event=observation_rejected observation_id=%s result=permanent",
                observation.observation_id,
                extra={
                    "event": "observation_rejected",
                    "observation_id": observation.observation_id,
                    "result": "permanent",
                },
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
            extra={
                "event": "delivery_retry",
                "observation_id": observation.observation_id,
                "attempt": retry,
                "delay_seconds": round(delay, 3),
            },
        )
        await asyncio.sleep(delay)
