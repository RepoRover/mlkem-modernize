"""Regression checks for audit findings without external services."""

import asyncio
import base64
from collections.abc import AsyncIterator
from datetime import date
from pathlib import Path

import asyncpg
import cloud.app as cloud_application
import gateway.app as gateway_application
import httpx
import pytest
from cloud.app import CloudService, create_app
from cloud.crypto import load_private_keys
from cloud.errors import CloudStartupError
from cloud.models import Observation as CloudObservation
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from gateway.app import GatewayService
from gateway.app import create_app as gateway_app
from gateway.crypto import encrypt_cloud_envelope
from gateway.errors import PermanentCloudError
from gateway.forwarding import CloudForwarder
from gateway.models import Observation
from pydantic import ValidationError


def observation() -> Observation:
    return Observation(
        observation_id="device-1:2024-01-01",
        device_id="device-1",
        observed_on=date(2024, 1, 1),
        latitude=1,
        longitude=2,
        elevation_m=3,
        utc_offset_seconds=0,
        timezone="UTC",
        timezone_abbreviation="UTC",
        temperature_max_c=2,
        temperature_min_c=1,
        precipitation_mm=0,
        wind_speed_max_kmh=0,
    )


class Store:
    def __init__(self):
        self.calls = 0

    async def start(self):
        pass

    async def close(self):
        pass

    async def health(self):
        return True

    async def insert(self, observation: CloudObservation) -> bool:
        self.calls += 1
        return True


def test_non_ascii_bearer_rejected_before_parsing():
    async def scenario():
        store = Store()
        app = create_app(service=CloudService("gw", "a" * 43, {}, store))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://cloud"
        ) as client:
            response = await client.post(
                "/v1/observations",
                content=b"not-json",
                headers=[(b"authorization", b"Bearer \xff")],
            )
        assert response.status_code == 401
        assert store.calls == 0

    asyncio.run(scenario())


def forwarder(client: httpx.AsyncClient) -> CloudForwarder:
    """Construct a valid forwarding dependency; unexpected calls fail the test."""
    return CloudForwarder(
        client=client,
        cloud_url="https://cloud",
        bearer_token="a" * 43,
        gateway_id="gw",
        kem_key_id="kem",
        public_key=MLKEM768PrivateKey.generate().public_key(),
        attempts=1,
        timeout_seconds=1,
        deadline_seconds=2,
        retry_initial_seconds=0,
        retry_max_seconds=0,
    )


def unexpected_request(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"Unexpected forwarding to {request.url.host}")


def test_gateway_validation_logs_do_not_include_field_names(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(unexpected_request)
        ) as upstream:
            service = GatewayService(
                "device-1", "key", b"x" * 32, "kem", forwarder(upstream)
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway_app(service=service)),
                base_url="https://gateway",
            ) as client:
                response = await client.post(
                    "/v1/observations", json={"SECRET_SENTINEL\nevent=forged": "x"}
                )
            assert response.status_code == 400

    asyncio.run(scenario())
    assert "extra_forbidden" in caplog.text
    assert "SECRET_SENTINEL" not in caplog.text
    assert "event=forged" not in caplog.text


@pytest.mark.parametrize("service_name", ["gateway", "cloud"])
def test_request_body_deadline_and_chunk_limit(
    service_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gateway_application, "REQUEST_BODY_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(cloud_application, "REQUEST_BODY_TIMEOUT_SECONDS", 0.01)

    async def scenario() -> None:
        async def stalled() -> AsyncIterator[bytes]:
            await asyncio.Event().wait()
            yield b""

        async def oversized() -> AsyncIterator[bytes]:
            yield b"x" * 32769

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(unexpected_request)
        ) as upstream:
            if service_name == "gateway":
                app = gateway_app(
                    service=GatewayService(
                        "device-1", "key", b"x" * 32, "kem", forwarder(upstream)
                    )
                )
            else:
                app = create_app(service=CloudService("gw", "a" * 43, {}, Store()))
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://service"
            ) as client:
                for body in (stalled(), oversized()):
                    response = await asyncio.wait_for(
                        client.post(
                            "/v1/observations",
                            content=body,
                            headers={
                                "Content-Type": "application/json",
                                "Authorization": "Bearer " + "a" * 43,
                            },
                        ),
                        timeout=1,
                    )
                    assert response.status_code == 400
                    assert response.json() == {"status": "rejected"}

    asyncio.run(scenario())


class EndlessResponse(httpx.AsyncByteStream):
    def __init__(self):
        self.count = 0
        self.closed = False

    async def __aiter__(self):
        for _ in range(1024):
            self.count += 4096
            yield b"x" * 4096

    async def aclose(self):
        self.closed = True


@pytest.mark.parametrize("status", [201, 503])
def test_gateway_bounds_success_and_error_response_streams(status: int) -> None:
    async def scenario():
        stream = EndlessResponse()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(status, stream=stream)
            )
        ) as client:
            forwarder = CloudForwarder(
                client=client,
                cloud_url="https://cloud",
                bearer_token="a" * 43,
                gateway_id="gw",
                kem_key_id="key",
                public_key=MLKEM768PrivateKey.generate().public_key(),
                attempts=1,
                timeout_seconds=1,
                deadline_seconds=2,
                retry_initial_seconds=0,
                retry_max_seconds=0,
            )
            with pytest.raises(PermanentCloudError, match="too large"):
                await forwarder.forward(observation())
        assert stream.count == 32768 + 4096
        assert stream.closed

    asyncio.run(scenario())


def test_device_bounds_response_stream(tmp_path: Path) -> None:
    from device.config import Settings as DeviceSettings
    from device.delivery import deliver
    from device.errors import DeviceError
    from device.models import Observation as DeviceObservation

    from tools.bootstrap import generate

    generate(tmp_path)
    settings = DeviceSettings.model_validate(
        {
            "DEVICE_ID": "device-1",
            "DEVICE_KEY_ID": "key",
            "DEVICE_KEY_FILE": tmp_path / "device.key",
            "GATEWAY_URL": "https://gateway",
            "GATEWAY_TIMEOUT_SECONDS": 1,
            "CA_CERT_FILE": tmp_path / "ca/ca.crt",
            "WEATHER_CSV_FILE": Path(__file__).resolve().parents[1]
            / "device/data/weather_data.csv",
            "SEND_INTERVAL_SECONDS": 0,
            "RETRY_INITIAL_SECONDS": 0.01,
            "RETRY_MAX_SECONDS": 0.01,
        }
    )

    async def scenario() -> None:
        stream = EndlessResponse()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(503, stream=stream))
        ) as client:
            with pytest.raises(DeviceError, match="too large"):
                await deliver(
                    client,
                    settings,
                    b"x" * 32,
                    DeviceObservation.model_validate_json(
                        observation().model_dump_json()
                    ),
                )
        assert stream.count == 32768 + 4096
        assert stream.closed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "field",
    [
        "version",
        "kem",
        "gateway_id",
        "kem_key_id",
        "observation_id",
        "kem_ciphertext",
        "nonce",
        "ciphertext",
    ],
)
def test_all_cloud_authenticated_fields_reject_tampering(field: str) -> None:
    async def scenario():
        key = MLKEM768PrivateKey.generate()
        store = Store()
        app = create_app(
            service=CloudService("gw", "a" * 43, {"key": key, "other": key}, store)
        )
        envelope = encrypt_cloud_envelope(
            observation(), "gw", "key", key.public_key()
        ).model_dump()
        if field in ("kem_ciphertext", "nonce", "ciphertext"):
            value = bytearray(base64.b64decode(envelope[field]))
            value[0] ^= 1
            envelope[field] = base64.b64encode(value).decode()
        else:
            envelope[field] = 2 if field == "version" else "other"
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://cloud"
        ) as client:
            result = await client.post(
                "/v1/observations",
                json=envelope,
                headers={"Authorization": "Bearer " + "a" * 43},
            )
        assert result.status_code == 400
        assert store.calls == 0

    asyncio.run(scenario())


def test_unicode_key_filename_is_rejected(tmp_path: Path):
    key = MLKEM768PrivateKey.generate()
    (tmp_path / "clé.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(CloudStartupError, match="filename"):
        load_private_keys(tmp_path)


def test_bootstrap_refuses_overwrite_and_separates_keys(tmp_path: Path) -> None:
    from tools.bootstrap import generate

    generate(tmp_path)
    original = (tmp_path / "device.key").read_bytes()
    assert len(original) == 32
    assert list(load_private_keys(tmp_path / "active")) == ["cloud-kem-001"]
    assert list(load_private_keys(tmp_path / "staged")) == ["cloud-kem-002"]
    assert (tmp_path / "device.key").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="--force"):
        generate(tmp_path)
    assert (tmp_path / "device.key").read_bytes() == original
    generate(tmp_path, force=True)
    assert (tmp_path / "device.key").read_bytes() != original


def test_invalid_token_configuration_rejected(tmp_path: Path) -> None:
    from gateway.app import build_service
    from gateway.config import Settings as GatewaySettings
    from gateway.errors import GatewayStartupError

    from tools.bootstrap import generate

    generate(tmp_path)
    settings = GatewaySettings.model_validate(
        {
            "DEVICE_ID": "device-1",
            "DEVICE_KEY_ID": "key",
            "DEVICE_KEY_FILE": tmp_path / "device.key",
            "GATEWAY_ID": "gw",
            "CLOUD_URL": "https://cloud",
            "CLOUD_CA_CERT_FILE": tmp_path / "ca/ca.crt",
            "CLOUD_API_TOKEN_FILE": tmp_path / "gateway.token",
            "MLKEM_KEY_ID": "cloud-kem-001",
            "MLKEM_PUBLIC_KEY_FILE": tmp_path / "public/cloud-kem-001.pub",
            "TLS_CERT_FILE": tmp_path / "gateway/tls.crt",
            "TLS_KEY_FILE": tmp_path / "gateway/tls.key",
        }
    )
    for invalid in ("é" * 40, "x" * 32 + "\ninjected", "short"):
        (tmp_path / "gateway.token").write_text(invalid)
        with pytest.raises(GatewayStartupError, match="bearer token"):
            build_service(settings)


def test_device_safe_validation_codes():
    from device.errors import validation_codes

    try:
        observation().__class__.model_validate({"SECRET\nFORGED": "value"})
    except ValidationError as error:
        codes = validation_codes(error)
        assert "SECRET" not in codes
        assert "extra_forbidden" in codes
        assert len(codes) <= 512


@pytest.mark.parametrize("compressed", [False, True])
def test_forwarding_deadline_and_compression_rejection(compressed: bool) -> None:
    from gateway.errors import TransientCloudError

    async def scenario():
        calls = 0
        stream = EndlessResponse()

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            assert request.headers["accept-encoding"] == "identity"
            if compressed:
                return httpx.Response(
                    201, headers={"Content-Encoding": "gzip"}, stream=stream
                )
            await asyncio.Event().wait()
            return httpx.Response(500)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            forwarder = CloudForwarder(
                client=client,
                cloud_url="https://cloud",
                bearer_token="a" * 43,
                gateway_id="gw",
                kem_key_id="key",
                public_key=MLKEM768PrivateKey.generate().public_key(),
                attempts=3,
                timeout_seconds=1,
                deadline_seconds=0.02,
                retry_initial_seconds=0,
                retry_max_seconds=0,
            )
            with pytest.raises(
                PermanentCloudError if compressed else TransientCloudError
            ):
                await asyncio.wait_for(forwarder.forward(observation()), timeout=1)
        assert calls == 1
        if compressed:
            assert stream.count == 0
            assert stream.closed

    asyncio.run(scenario())


def test_cancelled_database_shutdown_terminates_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cloud.database import PostgresStore

    async def scenario() -> None:
        entered = asyncio.Event()
        terminated = asyncio.Event()
        terminate = asyncpg.Pool.terminate

        async def stalled_close(pool: asyncpg.Pool) -> None:
            assert pool.get_size() == 0
            entered.set()
            await asyncio.Event().wait()

        def record_termination(pool: asyncpg.Pool) -> None:
            terminate(pool)
            terminated.set()

        monkeypatch.setattr(asyncpg.Pool, "close", stalled_close)
        monkeypatch.setattr(asyncpg.Pool, "terminate", record_termination)
        store = PostgresStore("postgresql://localhost/unused")
        await store.start()  # min_size=0: a real pool without opening connections
        task = asyncio.create_task(store.close())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert terminated.is_set()
        assert not await store.health()
        await store.close()  # repeated shutdown is safe

    asyncio.run(scenario())
