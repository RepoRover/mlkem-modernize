import asyncio
import base64
from datetime import date

import httpx
from cloud.app import CloudService, create_app
from cloud.models import Observation
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from gateway.crypto import encrypt_cloud_envelope
from gateway.models import Observation as GatewayObservation

GATEWAY_ID = "gateway-001"
KEY_ID = "cloud-kem-001"
TOKEN = "a" * 43


class MemoryStore:
    def __init__(self) -> None:
        self.rows: dict[str, Observation] = {}

    async def health(self) -> bool:
        return True

    async def insert(self, observation: Observation) -> bool:
        if observation.observation_id in self.rows:
            return False
        self.rows[observation.observation_id] = observation
        return True


def observation() -> GatewayObservation:
    return GatewayObservation(
        observation_id="weather-station-001:2024-01-01",
        device_id="weather-station-001",
        observed_on=date(2024, 1, 1),
        latitude=52.5,
        longitude=13.4,
        elevation_m=38,
        utc_offset_seconds=7200,
        timezone="Europe/Berlin",
        timezone_abbreviation="GMT+2",
        temperature_max_c=7.4,
        temperature_min_c=3.4,
        precipitation_mm=1.8,
        wind_speed_max_kmh=19.7,
    )


def test_store_and_duplicate_and_health() -> None:
    async def scenario() -> None:
        private_key = MLKEM768PrivateKey.generate()
        store = MemoryStore()
        service = CloudService(GATEWAY_ID, TOKEN, {KEY_ID: private_key}, store)
        envelope = encrypt_cloud_envelope(
            observation(), GATEWAY_ID, KEY_ID, private_key.public_key()
        ).model_dump()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(service=service)),
            base_url="https://cloud",
        ) as client:
            headers = {"Authorization": f"Bearer {TOKEN}"}
            health = await client.get("/healthz")
            first = await client.post(
                "/v1/observations", json=envelope, headers=headers
            )
            second = await client.post(
                "/v1/observations", json=envelope, headers=headers
            )
        assert health.status_code == 200
        assert first.status_code == 201 and first.json()["status"] == "stored"
        assert second.status_code == 200 and second.json()["status"] == "duplicate"
        assert len(store.rows) == 1

    asyncio.run(scenario())


def test_authentication_precedes_parsing_and_unknown_key_rejected() -> None:
    async def scenario() -> None:
        private_key = MLKEM768PrivateKey.generate()
        service = CloudService(GATEWAY_ID, TOKEN, {KEY_ID: private_key}, MemoryStore())
        app = create_app(service=service)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://cloud"
        ) as client:
            unauthorized = await client.post("/v1/observations", content=b"not-json")
            envelope = encrypt_cloud_envelope(
                observation(), GATEWAY_ID, KEY_ID, private_key.public_key()
            ).model_dump()
            envelope["kem_key_id"] = "unknown"
            unknown = await client.post(
                "/v1/observations",
                json=envelope,
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
        assert unauthorized.status_code == 401
        assert unknown.status_code == 400

    asyncio.run(scenario())


def test_ciphertext_and_authenticated_metadata_tampering_rejected() -> None:
    async def scenario() -> None:
        private_key = MLKEM768PrivateKey.generate()
        service = CloudService(GATEWAY_ID, TOKEN, {KEY_ID: private_key}, MemoryStore())
        original = encrypt_cloud_envelope(
            observation(), GATEWAY_ID, KEY_ID, private_key.public_key()
        ).model_dump()
        ciphertext = bytearray(base64.b64decode(original["ciphertext"], validate=True))
        ciphertext[0] ^= 1
        original["ciphertext"] = base64.b64encode(ciphertext).decode()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(service=service)),
            base_url="https://cloud",
        ) as client:
            response = await client.post(
                "/v1/observations",
                json=original,
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
        assert response.status_code == 400

    asyncio.run(scenario())
