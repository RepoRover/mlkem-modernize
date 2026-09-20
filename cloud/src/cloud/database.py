"""PostgreSQL persistence for Cloud observations."""

import asyncio
from typing import Protocol

import asyncpg

from cloud.errors import DatabaseError
from cloud.models import Observation

INSERT = """INSERT INTO observations (
 observation_id, device_id, observed_on, latitude, longitude, elevation_m,
 utc_offset_seconds, timezone, timezone_abbreviation, temperature_max_c,
 temperature_min_c, precipitation_mm, wind_speed_max_kmh
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (observation_id) DO NOTHING RETURNING observation_id"""

DATABASE_FAILURES = (asyncpg.PostgresError, OSError, asyncio.TimeoutError)


class ObservationStore(Protocol):
    """Persistence contract used by the HTTP service."""

    async def health(self) -> bool: ...

    async def insert(self, observation: Observation) -> bool: ...


class PostgresStore:
    """Short-transaction asyncpg observation store."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    async def health(self) -> bool:
        """Return whether PostgreSQL accepts a simple query."""
        connection: asyncpg.Connection | None = None
        try:
            active = await asyncpg.connect(self.database_url, timeout=3)
            connection = active
            return await active.fetchval("SELECT 1") == 1
        except DATABASE_FAILURES:
            return False
        finally:
            if connection is not None:
                await connection.close()

    async def insert(self, observation: Observation) -> bool:
        """Insert once and return true only for a newly stored row."""
        values = (
            observation.observation_id,
            observation.device_id,
            observation.observed_on,
            observation.latitude,
            observation.longitude,
            observation.elevation_m,
            observation.utc_offset_seconds,
            observation.timezone,
            observation.timezone_abbreviation,
            observation.temperature_max_c,
            observation.temperature_min_c,
            observation.precipitation_mm,
            observation.wind_speed_max_kmh,
        )
        connection: asyncpg.Connection | None = None
        try:
            active = await asyncpg.connect(self.database_url)
            connection = active
            async with active.transaction():
                inserted = await active.fetchval(INSERT, *values)
            return inserted is not None
        except DATABASE_FAILURES as error:
            raise DatabaseError("database operation failed") from error
        finally:
            if connection is not None:
                await connection.close()
