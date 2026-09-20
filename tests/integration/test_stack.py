"""Real HTTPS and PostgreSQL checks; run via the Compose integration tool."""

import asyncio
import os
import ssl
import time
import uuid
from datetime import date
from pathlib import Path

import asyncpg
import httpx
import pytest
from cloud.database import PostgresStore
from cloud.errors import DatabaseError
from cloud.models import Observation as CloudObservation
from crypto import encrypt_observation
from gateway.crypto import encrypt_cloud_envelope
from gateway.models import Observation
from models import Observation as DeviceObservation

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION") != "1",
    reason="requires Compose TLS/PostgreSQL stack",
)
MATERIAL = Path(os.environ.get("MATERIAL_DIR", ".local/material"))


def observation(
    device: str = "weather-station-001", day: str = "2050-01-01"
) -> Observation:
    return Observation(
        observation_id=f"{device}:{day}",
        device_id=device,
        observed_on=date.fromisoformat(day),
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


def client_context():
    return ssl.create_default_context(cafile=str(MATERIAL / "ca/ca.crt"))


def test_real_device_gateway_cloud_database_and_replay():
    async def scenario():
        context = client_context()
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        envelope = encrypt_observation(
            DeviceObservation.model_validate_json(observation().model_dump_json()),
            "device-key-001",
            (MATERIAL / "device.key").read_bytes(),
        ).model_dump()
        async with httpx.AsyncClient(
            verify=context, timeout=35, trust_env=False
        ) as client:
            response = None
            for _ in range(2):
                response = await client.post(
                    "https://gateway:8443/v1/observations", json=envelope
                )
                assert response.status_code in (200, 201), response.text
            assert response is not None
            assert response.json()["status"] == "duplicate"
        connection = await asyncpg.connect((MATERIAL / "database.url").read_text())
        try:
            assert (
                await connection.fetchval(
                    "SELECT count(*) FROM observations WHERE observation_id=$1",
                    observation().observation_id,
                )
                == 1
            )
        finally:
            await connection.close()

    asyncio.run(scenario())


def test_real_pool_idempotency_lock_timeout_and_recovery():
    async def scenario():
        dsn = (MATERIAL / "database.url").read_text()
        store = PostgresStore(dsn)
        await store.start()
        item = CloudObservation.model_validate_json(
            observation("audit-" + uuid.uuid4().hex).model_dump_json()
        )
        connection = await asyncpg.connect(dsn)
        try:
            assert await store.health()
            assert await store.insert(item)
            assert not await store.insert(item)
            async with connection.transaction():
                await connection.execute(
                    "LOCK TABLE observations IN ACCESS EXCLUSIVE MODE"
                )
                start = time.monotonic()
                with pytest.raises(DatabaseError):
                    await store.insert(item)
                assert time.monotonic() - start < 5.5
            assert await store.health()
            assert not await store.insert(item)
            # Saturate the pool through its public insert API, not private handles.
            async with connection.transaction():
                await connection.execute(
                    "LOCK TABLE observations IN ACCESS EXCLUSIVE MODE"
                )
                tasks = [asyncio.create_task(store.insert(item)) for _ in range(8)]
                try:
                    async with asyncio.timeout(1):
                        while True:
                            # PostgreSQL caches activity snapshots within a transaction.
                            await connection.execute("SELECT pg_stat_clear_snapshot()")
                            busy: int = await connection.fetchval(
                                "SELECT count(*) FROM pg_stat_activity "
                                "WHERE datname=current_database() AND state='active' "
                                "AND query LIKE 'INSERT INTO observations%'"
                            )
                            assert busy <= 4
                            if busy == 4:
                                break
                            await asyncio.sleep(0.01)
                finally:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                assert all(isinstance(result, DatabaseError) for result in results)
                assert any(
                    isinstance(result, DatabaseError)
                    and isinstance(result.__cause__, TimeoutError)
                    for result in results
                ), "Excess inserts must hit the pool acquisition deadline"
            assert await store.health()
            assert not await store.insert(item)
        finally:
            await connection.execute(
                "DELETE FROM observations WHERE observation_id=$1", item.observation_id
            )
            await connection.close()
            await store.close()

    asyncio.run(scenario())


def test_cloud_disallows_legacy_tls():
    async def scenario():
        context = client_context()
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        async with httpx.AsyncClient(
            verify=context, timeout=3, trust_env=False
        ) as client:
            with pytest.raises(httpx.ConnectError):
                await client.get("https://cloud:8443/healthz")

    asyncio.run(scenario())


def test_rotation():
    async def scenario():
        stage = os.environ.get("ROTATION_STAGE", "current")
        expected = {
            "current": (True, False),
            "overlap": (True, True),
            "retired": (False, True),
        }[stage]
        async with httpx.AsyncClient(
            verify=client_context(), timeout=10, trust_env=False
        ) as client:
            for key_id, accepted in zip(
                ("cloud-kem-001", "cloud-kem-002"),
                expected,
                strict=True,
            ):
                # The old public key is sufficient to test rejection after retirement.
                from cryptography.hazmat.primitives.asymmetric.mlkem import (
                    MLKEM768PublicKey,
                )

                public = MLKEM768PublicKey.from_public_bytes(
                    (MATERIAL / f"public/{key_id}.pub").read_bytes()
                )
                envelope = encrypt_cloud_envelope(
                    observation(day="2050-01-02"), "gateway-001", key_id, public
                )
                response = await client.post(
                    "https://cloud:8443/v1/observations",
                    json=envelope.model_dump(),
                    headers={
                        "Authorization": "Bearer "
                        + (MATERIAL / "gateway.token").read_text()
                    },
                )
                assert (response.status_code in (200, 201)) == accepted, response.text
                if not accepted:
                    assert response.status_code == 400

    asyncio.run(scenario())


def test_log_sanitization_over_real_tls():
    async def scenario():
        async with httpx.AsyncClient(
            verify=client_context(), timeout=3, trust_env=False
        ) as client:
            response = await client.post(
                "https://gateway:8443/v1/observations",
                json={"AUDIT_SECRET_SENTINEL\nevent=forged": "x"},
            )
        assert response.status_code == 400
        assert "AUDIT_SECRET_SENTINEL" not in response.text

    asyncio.run(scenario())
