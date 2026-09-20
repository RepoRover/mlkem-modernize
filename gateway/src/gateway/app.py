"""FastAPI application for the trusted Gateway boundary."""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from gateway.config import Settings
from gateway.crypto import decrypt_device_envelope, load_mlkem_public_key
from gateway.errors import (
    DeviceAuthenticationError,
    EnvelopeError,
    GatewayStartupError,
    ObservationValidationError,
    PermanentCloudError,
    TransientCloudError,
    validation_codes,
)
from gateway.forwarding import CloudForwarder
from gateway.models import DeviceEnvelope

logger = logging.getLogger("gateway")
MAX_REQUEST_BODY_BYTES = 32 * 1024
REQUEST_BODY_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class GatewayService:
    """Loaded Device identity and Cloud forwarding dependencies."""

    device_id: str
    device_key_id: str
    device_key: bytes
    kem_key_id: str
    forwarder: CloudForwarder


async def _request_body(request: Request) -> bytes:
    """Read a request body while enforcing the pre-parse size bound."""
    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type.lower() != "application/json":
        raise EnvelopeError("request content type must be application/json")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                raise EnvelopeError("request body exceeds protocol limit")
        except ValueError as error:
            raise EnvelopeError("request content length is invalid") from error

    body = bytearray()
    try:
        async with asyncio.timeout(REQUEST_BODY_TIMEOUT_SECONDS):
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_REQUEST_BODY_BYTES:
                    raise EnvelopeError("request body exceeds protocol limit")
                body.extend(chunk)
    except TimeoutError as error:
        raise EnvelopeError("request body deadline expired") from error
    return bytes(body)


def _read_device_key(settings: Settings) -> bytes:
    """Read and validate the provisioned Device AES key."""
    try:
        key = settings.device_key_file.read_bytes()
    except OSError as error:
        raise GatewayStartupError("Device AES key could not be read") from error
    if len(key) != 32:
        raise GatewayStartupError("Device AES key must be exactly 32 bytes")
    return key


def _read_bearer_token(settings: Settings) -> str:
    """Read the provisioned Cloud bearer token without logging it."""
    try:
        token = settings.cloud_api_token_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise GatewayStartupError("Cloud bearer token could not be read") from error
    if (
        len(token) < 32
        or re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token, re.ASCII) is None
    ):
        raise GatewayStartupError("Cloud bearer token has invalid length or syntax")
    return token


def _validate_server_tls(settings: Settings) -> None:
    """Load Gateway TLS material and require TLS 1.2 or newer."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(
            certfile=str(settings.tls_cert_file), keyfile=str(settings.tls_key_file)
        )
    except (OSError, ssl.SSLError) as error:
        raise GatewayStartupError("Gateway TLS material could not be loaded") from error


def _cloud_client(settings: Settings) -> httpx.AsyncClient:
    """Create a certificate-verifying TLS-1.3-only Cloud client."""
    try:
        context = ssl.create_default_context(cafile=str(settings.cloud_ca_cert_file))
    except (OSError, ssl.SSLError) as error:
        raise GatewayStartupError("Cloud CA certificate could not be loaded") from error
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return httpx.AsyncClient(verify=context, follow_redirects=False, timeout=None)


def build_service(
    settings: Settings, client: httpx.AsyncClient | None = None
) -> GatewayService:
    """Load Gateway key material and construct its Cloud forwarder."""
    device_key = _read_device_key(settings)
    bearer_token = _read_bearer_token(settings)
    public_key = load_mlkem_public_key(settings.mlkem_public_key_file)
    _validate_server_tls(settings)
    cloud_client = client or _cloud_client(settings)
    return GatewayService(
        device_id=settings.device_id,
        device_key_id=settings.device_key_id,
        device_key=device_key,
        kem_key_id=settings.mlkem_key_id,
        forwarder=CloudForwarder(
            client=cloud_client,
            cloud_url=str(settings.cloud_url),
            bearer_token=bearer_token,
            gateway_id=settings.gateway_id,
            kem_key_id=settings.mlkem_key_id,
            public_key=public_key,
            attempts=settings.cloud_retry_attempts,
            timeout_seconds=settings.cloud_timeout_seconds,
            deadline_seconds=settings.cloud_forward_deadline_seconds,
            retry_initial_seconds=settings.cloud_retry_initial_seconds,
            retry_max_seconds=settings.cloud_retry_max_seconds,
        ),
    )


def create_app(
    *,
    settings: Settings | None = None,
    service: GatewayService | None = None,
) -> FastAPI:
    """Create the Gateway API, optionally with injected test dependencies."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        loaded = service
        owns_client = False
        if loaded is None:
            try:
                configured = settings or Settings.from_environment()
                loaded = build_service(configured)
                owns_client = True
            except ValidationError as error:
                logger.error(
                    "event=settings_rejected errors=%s", validation_codes(error)
                )
                raise RuntimeError("Gateway settings are invalid") from None
            except GatewayStartupError as error:
                logger.error("event=startup_rejected error=%s", error)
                raise RuntimeError("Gateway startup material is invalid") from None
        app.state.service = loaded
        logger.info(
            "event=settings_keys_loaded device_id=%s key_id=%s kem_key_id=%s",
            loaded.device_id,
            loaded.device_key_id,
            loaded.kem_key_id,
        )
        logger.info("event=service_ready")
        try:
            yield
        finally:
            if owns_client:
                await loaded.forwarder.close()
            logger.info("event=service_stopping")

    app = FastAPI(title="ML-KEM Modernize Gateway", lifespan=lifespan)
    if service is not None:
        app.state.service = service

    @app.get("/healthz")
    async def health(request: Request) -> JSONResponse:
        """Report readiness after all local Gateway material is loaded."""
        if getattr(request.app.state, "service", None) is None:
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return JSONResponse(status_code=200, content={"status": "ok"})

    @app.post("/v1/observations")
    async def observations(request: Request) -> JSONResponse:
        """Decrypt one Device observation and synchronously forward it."""
        loaded: GatewayService = request.app.state.service
        try:
            body = await _request_body(request)
            envelope = DeviceEnvelope.model_validate_json(body)
        except EnvelopeError:
            logger.warning("event=observation_rejected result=malformed_envelope")
            return JSONResponse(status_code=400, content={"status": "rejected"})
        except ValidationError as error:
            logger.warning(
                "event=observation_rejected result=malformed_envelope errors=%s",
                validation_codes(error),
            )
            return JSONResponse(status_code=400, content={"status": "rejected"})

        try:
            observation = decrypt_device_envelope(
                envelope,
                loaded.device_id,
                loaded.device_key_id,
                loaded.device_key,
            )
        except EnvelopeError:
            logger.warning(
                "event=observation_rejected observation_id=%s result=malformed_envelope",
                envelope.observation_id,
            )
            return JSONResponse(status_code=400, content={"status": "rejected"})
        except DeviceAuthenticationError:
            logger.warning(
                "event=observation_rejected observation_id=%s result=authentication",
                envelope.observation_id,
            )
            return JSONResponse(status_code=401, content={"status": "rejected"})
        except ObservationValidationError:
            logger.warning(
                "event=observation_rejected observation_id=%s result=validation",
                envelope.observation_id,
            )
            return JSONResponse(status_code=422, content={"status": "rejected"})

        try:
            result = await loaded.forwarder.forward(observation)
        except PermanentCloudError:
            logger.error(
                "event=observation_rejected observation_id=%s result=upstream_rejected",
                observation.observation_id,
            )
            return JSONResponse(
                status_code=502, content={"status": "upstream_rejected"}
            )
        except TransientCloudError:
            logger.warning(
                "event=observation_rejected observation_id=%s result=retry",
                observation.observation_id,
            )
            return JSONResponse(status_code=503, content={"status": "retry"})
        except Exception:  # noqa: BLE001 - never expose an unexpected error value
            logger.error(
                "event=observation_rejected observation_id=%s result=internal",
                observation.observation_id,
            )
            return JSONResponse(status_code=503, content={"status": "retry"})

        status_code = 201 if result.status == "stored" else 200
        logger.info(
            "event=observation_accepted observation_id=%s key_id=%s result=%s",
            result.observation_id,
            loaded.kem_key_id,
            result.status,
        )
        return JSONResponse(status_code=status_code, content=result.model_dump())

    return app
