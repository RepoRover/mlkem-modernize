"""Bounded synchronous forwarding from Gateway to Cloud."""

from __future__ import annotations

import asyncio
import logging
import math
import ssl
from enum import StrEnum

import httpx
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from opentelemetry import trace
from pydantic import ValidationError

from gateway.crypto import encrypt_cloud_envelope
from gateway.errors import PermanentCloudError, TransientCloudError
from gateway.models import CloudResult, Observation

logger = logging.getLogger("gateway")
tracer = trace.get_tracer("gateway.forwarding")
MAX_CLOUD_RESPONSE_BYTES = 32 * 1024


class CloudResponseAction(StrEnum):
    """How Gateway handles one Cloud response."""

    ACCEPT = "accept"
    RETRY = "retry"
    REJECT = "reject"


def classify_cloud_status(status_code: int) -> CloudResponseAction:
    """Classify a Cloud HTTP status according to the forwarding contract."""
    if status_code in (200, 201):
        return CloudResponseAction.ACCEPT
    if status_code in (408, 429) or status_code >= 500:
        return CloudResponseAction.RETRY
    return CloudResponseAction.REJECT


def retry_delay(initial: float, maximum: float, retry: int) -> float:
    """Return deterministic capped exponential delay for a bounded retry loop."""
    try:
        return min(maximum, math.ldexp(initial, retry - 1))
    except OverflowError:
        return maximum


def _certificate_error(error: BaseException) -> bool:
    """Return whether an exception chain contains TLS certificate rejection."""
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if isinstance(current, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


class CloudForwarder:
    """Encrypt observations and forward them with bounded retries."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        cloud_url: str,
        bearer_token: str,
        gateway_id: str,
        kem_key_id: str,
        public_key: MLKEM768PublicKey,
        attempts: int,
        timeout_seconds: float,
        deadline_seconds: float,
        retry_initial_seconds: float,
        retry_max_seconds: float,
    ) -> None:
        self._client = client
        self._cloud_url = cloud_url
        self._bearer_token = bearer_token
        self._gateway_id = gateway_id
        self._kem_key_id = kem_key_id
        self._public_key = public_key
        self._attempts = attempts
        self._timeout_seconds = timeout_seconds
        self._deadline_seconds = deadline_seconds
        self._retry_initial_seconds = retry_initial_seconds
        self._retry_max_seconds = retry_max_seconds

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def forward(self, observation: Observation) -> CloudResult:
        """Forward one observation within the configured total deadline."""
        try:
            async with asyncio.timeout(self._deadline_seconds):
                return await self._forward_with_retries(observation)
        except TimeoutError as error:
            logger.warning(
                "event=forwarding_exhausted observation_id=%s key_id=%s result=deadline",
                observation.observation_id,
                self._kem_key_id,
                extra={
                    "event": "forwarding_exhausted",
                    "observation_id": observation.observation_id,
                    "key_id": self._kem_key_id,
                    "result": "deadline",
                },
            )
            raise TransientCloudError("Cloud forwarding deadline expired") from error

    async def _forward_with_retries(self, observation: Observation) -> CloudResult:
        """Create a fresh envelope for each bounded Cloud attempt."""
        for attempt in range(1, self._attempts + 1):
            with tracer.start_as_current_span(
                "gateway.encrypt",
                attributes={
                    "crypto.algorithm": "ML-KEM-768/HKDF-SHA256/AES-256-GCM",
                    "retry.attempt": attempt,
                },
            ):
                envelope = encrypt_cloud_envelope(
                    observation,
                    self._gateway_id,
                    self._kem_key_id,
                    self._public_key,
                )
            try:
                async with asyncio.timeout(self._timeout_seconds):
                    async with self._client.stream(
                        "POST",
                        self._cloud_url,
                        json=envelope.model_dump(),
                        headers={
                            "Authorization": f"Bearer {self._bearer_token}",
                            "Content-Type": "application/json",
                            "Accept-Encoding": "identity",
                        },
                    ) as response:
                        if (
                            response.headers.get("content-encoding", "identity").lower()
                            != "identity"
                        ):
                            raise PermanentCloudError(
                                "Compressed Cloud responses are unsupported"
                            )
                        body = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=4096):
                            if len(body) + len(chunk) > MAX_CLOUD_RESPONSE_BYTES:
                                raise PermanentCloudError("Cloud response is too large")
                            body.extend(chunk)
                        bounded_response = httpx.Response(
                            response.status_code, content=bytes(body)
                        )
            except (httpx.RequestError, TimeoutError) as error:
                if _certificate_error(error):
                    raise PermanentCloudError(
                        "Cloud certificate verification failed"
                    ) from error
                action = CloudResponseAction.RETRY
            else:
                action = classify_cloud_status(bounded_response.status_code)
                if action is CloudResponseAction.ACCEPT:
                    return self._validate_success(bounded_response, observation)
                if action is CloudResponseAction.REJECT:
                    raise PermanentCloudError("Cloud rejected Gateway request")

            if attempt == self._attempts:
                break
            delay = retry_delay(
                self._retry_initial_seconds, self._retry_max_seconds, attempt
            )
            logger.warning(
                "event=forwarding_retry observation_id=%s key_id=%s attempt=%d",
                observation.observation_id,
                self._kem_key_id,
                attempt + 1,
                extra={
                    "event": "forwarding_retry",
                    "observation_id": observation.observation_id,
                    "key_id": self._kem_key_id,
                    "attempt": attempt + 1,
                },
            )
            await asyncio.sleep(delay)

        logger.warning(
            "event=forwarding_exhausted observation_id=%s key_id=%s result=attempts",
            observation.observation_id,
            self._kem_key_id,
            extra={
                "event": "forwarding_exhausted",
                "observation_id": observation.observation_id,
                "key_id": self._kem_key_id,
                "result": "attempts",
            },
        )
        raise TransientCloudError("Cloud forwarding attempts exhausted")

    @staticmethod
    def _validate_success(
        response: httpx.Response, observation: Observation
    ) -> CloudResult:
        """Validate Cloud's bounded success response and status pairing."""
        if len(response.content) > MAX_CLOUD_RESPONSE_BYTES:
            raise PermanentCloudError("Cloud response is too large")
        try:
            result = CloudResult.model_validate_json(response.content)
        except ValidationError as error:
            raise PermanentCloudError("Cloud success response is malformed") from error
        expected_status = "stored" if response.status_code == 201 else "duplicate"
        if (
            result.observation_id != observation.observation_id
            or result.status != expected_status
        ):
            raise PermanentCloudError("Cloud success response does not match request")
        return result
