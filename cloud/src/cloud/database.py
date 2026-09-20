"""Bounded PostgreSQL persistence for Cloud observations."""

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

DATABASE_FAILURES = (
    asyncpg.PostgresError,
    asyncpg.InterfaceError,
    OSError,
    TimeoutError,
    ValueError,
)


class ObservationStore(Protocol):
    """Persistence contract used by the HTTP service."""

    async def start(self) -> None: ...

    async def close(self) -> None: ...

    async def health(self) -> bool: ...

    async def insert(self, observation: Observation) -> bool: ...


class PostgresStore:
    """Use a small connection pool with bounded acquisition and operations.

    Server-side limits also stop abandoned statements after a client disconnect.
    The operation deadline includes connection acquisition and transaction commit.
    """

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url
        self._pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        """Create the pool without requiring the database to be available yet."""
        try:
            self._pool = await asyncpg.create_pool(
                self._database_url,
                min_size=0,
                max_size=4,
                timeout=2,
                command_timeout=3,
                server_settings={"statement_timeout": "3000", "lock_timeout": "2000"},
            )
        except DATABASE_FAILURES as error:
            raise DatabaseError("database pool initialization failed") from error

    async def close(self) -> None:
        """Close connections, forcibly terminating them if cleanup stalls."""
        pool, self._pool = self._pool, None
        if pool is not None:
            try:
                async with asyncio.timeout(3):
                    await pool.close()
            except TimeoutError, asyncio.CancelledError:
                pool.terminate()
                raise

    async def health(self) -> bool:
        """Bound both connection acquisition and the readiness query."""
        if self._pool is None:
            return False
        try:
            async with asyncio.timeout(3):
                async with self._pool.acquire(timeout=2) as connection:
                    return await connection.fetchval("SELECT 1") == 1
        except DATABASE_FAILURES:
            return False

    async def insert(self, observation: Observation) -> bool:
        """Commit one insert within five seconds or return a retryable failure."""
        if self._pool is None:
            raise DatabaseError("database pool is not initialized")
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
        try:
            async with asyncio.timeout(5):
                async with self._pool.acquire(timeout=2) as connection:
                    async with connection.transaction():
                        inserted = await connection.fetchval(INSERT, *values)
                    return inserted is not None
        except DATABASE_FAILURES as error:
            raise DatabaseError("database operation failed") from error
