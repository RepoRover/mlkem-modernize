import asyncio
import base64
import json
from datetime import date
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from device.config import Settings as DeviceSettings
from device.delivery import deliver
from device.errors import DeviceError
from device.models import Location
from device.models import Observation as DeviceObservation
from gateway.app import GatewayService, create_app
from gateway.crypto import cloud_aad, cloud_hkdf_info
from gateway.forwarding import (
    CloudForwarder,
    CloudResponseAction,
    classify_cloud_status,
)
from gateway.models import CloudEnvelope
from gateway.models import Observation as GatewayObservation

DEVICE_ID = "weather-station-001"
DEVICE_KEY_ID = "device-key-001"
GATEWAY_ID = "gateway-001"
KEM_KEY_ID = "cloud-kem-001"
TOKEN = "a" * 43


def _device_observation() -> DeviceObservation:
    return DeviceObservation(
        observation_id=f"{DEVICE_ID}:2024-01-01",
        device_id=DEVICE_ID,
        observed_on=date(2024, 1, 1),
        temperature_max_c=7.4,
        temperature_min_c=3.4,
        precipitation_mm=1.8,
        wind_speed_max_kmh=19.7,
        **Location(
            latitude=52.54833,
            longitude=13.407822,
            elevation_m=38,
            utc_offset_seconds=7200,
            timezone="Europe/Berlin",
            timezone_abbreviation="GMT+2",
        ).model_dump(),
    )


def _device_settings(tmp_path: Path, key_file: Path) -> DeviceSettings:
    placeholder = tmp_path / "placeholder"
    placeholder.write_text("placeholder", encoding="utf-8")
    return DeviceSettings.model_validate(
        {
            "DEVICE_ID": DEVICE_ID,
            "DEVICE_KEY_ID": DEVICE_KEY_ID,
            "DEVICE_KEY_FILE": key_file,
            "GATEWAY_URL": "https://gateway/v1/observations",
            "GATEWAY_TIMEOUT_SECONDS": 2,
            "CA_CERT_FILE": placeholder,
            "WEATHER_CSV_FILE": placeholder,
            "SEND_INTERVAL_SECONDS": 0,
            "RETRY_INITIAL_SECONDS": 0.001,
            "RETRY_MAX_SECONDS": 0.001,
            "MAX_CYCLES": 1,
        }
    )


def _decrypt_cloud_envelope(
    request: httpx.Request, private_key: MLKEM768PrivateKey
) -> tuple[CloudEnvelope, GatewayObservation]:
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    envelope = CloudEnvelope.model_validate(json.loads(request.content))
    kem_ciphertext = base64.b64decode(envelope.kem_ciphertext, validate=True)
    shared_secret = private_key.decapsulate(kem_ciphertext)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=cloud_hkdf_info(envelope.kem_key_id),
    ).derive(shared_secret)
    plaintext = AESGCM(key).decrypt(
        base64.b64decode(envelope.nonce, validate=True),
        base64.b64decode(envelope.ciphertext, validate=True),
        cloud_aad(envelope),
    )
    return envelope, GatewayObservation.model_validate_json(plaintext)


def _service(
    device_key: bytes,
    private_key: MLKEM768PrivateKey,
    handler: httpx.MockTransport,
    *,
    attempts: int = 2,
) -> tuple[GatewayService, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=handler)
    forwarder = CloudForwarder(
        client=client,
        cloud_url="https://cloud/v1/observations",
        bearer_token=TOKEN,
        gateway_id=GATEWAY_ID,
        kem_key_id=KEM_KEY_ID,
        public_key=private_key.public_key(),
        attempts=attempts,
        timeout_seconds=1,
        deadline_seconds=2,
        retry_initial_seconds=0,
        retry_max_seconds=0,
    )
    return (
        GatewayService(
            device_id=DEVICE_ID,
            device_key_id=DEVICE_KEY_ID,
            device_key=device_key,
            kem_key_id=KEM_KEY_ID,
            forwarder=forwarder,
        ),
        client,
    )


def test_legacy_device_to_gateway_to_cloud_integration(tmp_path: Path) -> None:
    async def scenario() -> None:
        device_key = bytes(range(32))
        key_file = tmp_path / "device.key"
        key_file.write_bytes(device_key)
        private_key = MLKEM768PrivateKey.generate()
        envelopes: list[CloudEnvelope] = []
        forwarded: list[GatewayObservation] = []

        def cloud(request: httpx.Request) -> httpx.Response:
            envelope, observation = _decrypt_cloud_envelope(request, private_key)
            envelopes.append(envelope)
            if len(envelopes) == 1:
                return httpx.Response(503, json={"status": "retry"})
            forwarded.append(observation)
            return httpx.Response(
                201,
                json={
                    "observation_id": observation.observation_id,
                    "status": "stored",
                },
            )

        service, cloud_client = _service(
            device_key, private_key, httpx.MockTransport(cloud)
        )
        app = create_app(service=service)
        transport = httpx.ASGITransport(app=app)
        async with (
            cloud_client,
            httpx.AsyncClient(
                transport=transport, base_url="https://gateway"
            ) as gateway_client,
        ):
            accepted = await deliver(
                gateway_client,
                _device_settings(tmp_path, key_file),
                device_key,
                _device_observation(),
            )

        assert accepted is True
        assert forwarded[0].observation_id == f"{DEVICE_ID}:2024-01-01"
        assert len(envelopes) == 2
        assert envelopes[0].kem_ciphertext != envelopes[1].kem_ciphertext
        assert envelopes[0].nonce != envelopes[1].nonce

    asyncio.run(scenario())


def test_gateway_rejects_tampering_before_cloud(tmp_path: Path) -> None:
    async def scenario() -> None:
        from device.crypto import encrypt_observation

        device_key = bytes(range(32))
        private_key = MLKEM768PrivateKey.generate()
        cloud_calls = 0

        def cloud(_: httpx.Request) -> httpx.Response:
            nonlocal cloud_calls
            cloud_calls += 1
            return httpx.Response(500)

        service, cloud_client = _service(
            device_key, private_key, httpx.MockTransport(cloud)
        )
        envelope = encrypt_observation(
            _device_observation(), DEVICE_KEY_ID, device_key
        ).model_dump()
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext"], validate=True))
        ciphertext[0] ^= 1
        envelope["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")

        transport = httpx.ASGITransport(app=create_app(service=service))
        async with (
            cloud_client,
            httpx.AsyncClient(
                transport=transport, base_url="https://gateway"
            ) as gateway_client,
        ):
            response = await gateway_client.post("/v1/observations", json=envelope)
            malformed = await gateway_client.post(
                "/v1/observations",
                content=b'{"version":1}',
                headers={"Content-Type": "application/json"},
            )

        assert response.status_code == 401
        assert response.json() == {"status": "rejected"}
        assert malformed.status_code == 400
        assert cloud_calls == 0

    asyncio.run(scenario())


def test_permanent_cloud_rejection_is_fatal_to_device(tmp_path: Path) -> None:
    async def scenario() -> None:
        device_key = bytes(range(32))
        key_file = tmp_path / "device.key"
        key_file.write_bytes(device_key)
        private_key = MLKEM768PrivateKey.generate()
        cloud_calls = 0

        def cloud(_: httpx.Request) -> httpx.Response:
            nonlocal cloud_calls
            cloud_calls += 1
            return httpx.Response(401, json={"status": "rejected"})

        service, cloud_client = _service(
            device_key, private_key, httpx.MockTransport(cloud), attempts=3
        )
        transport = httpx.ASGITransport(app=create_app(service=service))
        async with (
            cloud_client,
            httpx.AsyncClient(
                transport=transport, base_url="https://gateway"
            ) as gateway_client,
        ):
            with pytest.raises(DeviceError, match="fatal"):
                await deliver(
                    gateway_client,
                    _device_settings(tmp_path, key_file),
                    device_key,
                    _device_observation(),
                )

        assert cloud_calls == 1

    asyncio.run(scenario())


def test_cloud_status_classification() -> None:
    assert classify_cloud_status(201) is CloudResponseAction.ACCEPT
    assert classify_cloud_status(408) is CloudResponseAction.RETRY
    assert classify_cloud_status(429) is CloudResponseAction.RETRY
    assert classify_cloud_status(503) is CloudResponseAction.RETRY
    assert classify_cloud_status(401) is CloudResponseAction.REJECT
