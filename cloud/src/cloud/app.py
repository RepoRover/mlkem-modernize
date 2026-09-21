"""FastAPI application for Cloud decryption and persistence."""

from __future__ import annotations

import asyncio
import hmac
import logging
import re
import ssl
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from opentelemetry import trace
from pydantic import ValidationError

from cloud.config import Settings
from cloud.crypto import decrypt_cloud_envelope, load_private_keys
from cloud.database import ObservationStore, PostgresStore
from cloud.errors import (
    CloudStartupError,
    DatabaseError,
    EnvelopeError,
    ObservationValidationError,
    validation_codes,
)
from cloud.models import CloudEnvelope

logger = logging.getLogger("cloud")
tracer = trace.get_tracer("cloud.app")
MAX_REQUEST_BODY_BYTES = 32 * 1024
REQUEST_BODY_TIMEOUT_SECONDS = 5
BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+={0,}$", re.ASCII)


@dataclass(frozen=True)
class CloudService:
    """Loaded Cloud authentication, cryptography, and storage dependencies."""

    gateway_id: str
    bearer_token: str
    private_keys: dict[str, MLKEM768PrivateKey]
    store: ObservationStore


def _read_text(path: Path, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise CloudStartupError(f"{label} could not be read") from error
    if not value:
        raise CloudStartupError(f"{label} is empty")
    return value


def _validate_tls(settings: Settings) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        context.load_cert_chain(str(settings.tls_cert_file), str(settings.tls_key_file))
    except (OSError, ssl.SSLError) as error:
        raise CloudStartupError("Cloud TLS material could not be loaded") from error


def build_service(settings: Settings) -> CloudService:
    """Load Cloud material and construct its PostgreSQL store."""
    token = _read_text(settings.gateway_api_token_file, "Gateway bearer token")
    if len(token) < 32 or BEARER_TOKEN.fullmatch(token) is None:
        raise CloudStartupError("Gateway bearer token has invalid length or syntax")
    database_url = _read_text(settings.database_url_file, "database URL")
    _validate_tls(settings)
    return CloudService(
        settings.gateway_id,
        token,
        load_private_keys(settings.key_directory),
        PostgresStore(database_url),
    )


async def _request_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type.lower() != "application/json":
        raise EnvelopeError("request content type must be application/json")
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > MAX_REQUEST_BODY_BYTES:
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


def _authorized(request: Request, token: str) -> bool:
    supplied = request.headers.get("authorization", "")
    prefix = "Bearer "
    if not supplied.startswith(prefix):
        return False
    candidate = supplied[len(prefix) :]
    if BEARER_TOKEN.fullmatch(candidate) is None:
        return False
    return hmac.compare_digest(candidate.encode("ascii"), token.encode("utf-8"))


def create_app(
    *, settings: Settings | None = None, service: CloudService | None = None
) -> FastAPI:
    """Create the Cloud API, optionally with injected test dependencies."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        loaded = service
        if loaded is None:
            try:
                loaded = build_service(settings or Settings.from_environment())
            except ValidationError as error:
                codes = validation_codes(error)
                logger.error(
                    "event=settings_rejected errors=%s",
                    codes,
                    extra={"event": "settings_rejected", "errors": codes},
                )
                raise RuntimeError("Cloud settings are invalid") from None
            except CloudStartupError as error:
                logger.error(
                    "event=startup_rejected error=%s",
                    error,
                    extra={"event": "startup_rejected", "error": str(error)},
                )
                raise RuntimeError("Cloud startup material is invalid") from None
        try:
            await loaded.store.start()
        except DatabaseError:
            raise RuntimeError("Cloud database initialization failed") from None
        app.state.service = loaded
        key_ids = sorted(loaded.private_keys)
        logger.info(
            "event=settings_keys_loaded gateway_id=%s key_ids=%s",
            loaded.gateway_id,
            key_ids,
            extra={
                "event": "settings_keys_loaded",
                "gateway_id": loaded.gateway_id,
                "key_ids": key_ids,
            },
        )
        logger.info("event=service_ready", extra={"event": "service_ready"})
        try:
            yield
        finally:
            try:
                await loaded.store.close()
            except TimeoutError:
                logger.warning(
                    "event=database_cleanup_timeout",
                    extra={"event": "database_cleanup_timeout"},
                )
            logger.info("event=service_stopping", extra={"event": "service_stopping"})

    app = FastAPI(title="ML-KEM Modernize Cloud", lifespan=lifespan)
    if service is not None:
        app.state.service = service

    @app.get("/healthz")
    async def health(request: Request) -> JSONResponse:
        loaded: CloudService | None = getattr(request.app.state, "service", None)
        if loaded is None or not await loaded.store.health():
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return JSONResponse(status_code=200, content={"status": "ok"})

    @app.post("/v1/observations")
    async def observations(request: Request) -> JSONResponse:
        loaded: CloudService = request.app.state.service
        if not _authorized(request, loaded.bearer_token):
            logger.warning(
                "event=observation_rejected result=authentication",
                extra={
                    "event": "observation_rejected",
                    "result": "authentication",
                },
            )
            return JSONResponse(status_code=401, content={"status": "rejected"})
        try:
            envelope = CloudEnvelope.model_validate_json(await _request_body(request))
        except EnvelopeError, ValidationError:
            logger.warning(
                "event=observation_rejected result=malformed_envelope",
                extra={
                    "event": "observation_rejected",
                    "result": "malformed_envelope",
                },
            )
            return JSONResponse(status_code=400, content={"status": "rejected"})
        if envelope.gateway_id != loaded.gateway_id:
            logger.warning(
                "event=observation_rejected observation_id=%s result=gateway_identity",
                envelope.observation_id,
                extra={
                    "event": "observation_rejected",
                    "observation_id": envelope.observation_id,
                    "result": "gateway_identity",
                },
            )
            return JSONResponse(status_code=400, content={"status": "rejected"})
        private_key = loaded.private_keys.get(envelope.kem_key_id)
        if private_key is None:
            logger.warning(
                "event=key_id_unknown observation_id=%s key_id=%s",
                envelope.observation_id,
                envelope.kem_key_id,
                extra={
                    "event": "key_id_unknown",
                    "observation_id": envelope.observation_id,
                    "key_id": envelope.kem_key_id,
                },
            )
            return JSONResponse(status_code=400, content={"status": "rejected"})
        try:
            with tracer.start_as_current_span(
                "cloud.decrypt",
                attributes={
                    "crypto.algorithm": "ML-KEM-768/HKDF-SHA256/AES-256-GCM",
                    "observation.id": envelope.observation_id,
                },
            ):
                observation = decrypt_cloud_envelope(envelope, private_key)
        except EnvelopeError:
            logger.warning(
                "event=observation_rejected observation_id=%s result=cryptographic",
                envelope.observation_id,
                extra={
                    "event": "observation_rejected",
                    "observation_id": envelope.observation_id,
                    "result": "cryptographic",
                },
            )
            return JSONResponse(status_code=400, content={"status": "rejected"})
        except ObservationValidationError:
            logger.warning(
                "event=observation_rejected observation_id=%s result=validation",
                envelope.observation_id,
                extra={
                    "event": "observation_rejected",
                    "observation_id": envelope.observation_id,
                    "result": "validation",
                },
            )
            return JSONResponse(status_code=422, content={"status": "rejected"})
        try:
            with tracer.start_as_current_span(
                "cloud.store",
                attributes={"db.system.name": "postgresql"},
            ) as store_span:
                stored = await loaded.store.insert(observation)
                store_span.set_attribute(
                    "observation.result", "stored" if stored else "duplicate"
                )
        except DatabaseError:
            logger.error(
                "event=observation_rejected observation_id=%s result=database",
                observation.observation_id,
                extra={
                    "event": "observation_rejected",
                    "observation_id": observation.observation_id,
                    "result": "database",
                },
            )
            return JSONResponse(status_code=503, content={"status": "retry"})
        status = "stored" if stored else "duplicate"
        event = f"observation_{status}"
        logger.info(
            "event=observation_%s observation_id=%s key_id=%s",
            status,
            observation.observation_id,
            envelope.kem_key_id,
            extra={
                "event": event,
                "observation_id": observation.observation_id,
                "key_id": envelope.kem_key_id,
                "result": status,
            },
        )
        return JSONResponse(
            status_code=201 if stored else 200,
            content={"observation_id": observation.observation_id, "status": status},
        )

    return app
