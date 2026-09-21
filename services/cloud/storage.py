"""SQLite storage for accepted readings.

One table, primary key (device_id, date). Re-sending a date updates it, which is
what we want because the device loops over the same year of data.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS readings (
    device_id     TEXT    NOT NULL,
    date          TEXT    NOT NULL,
    temp_max_c    REAL    NOT NULL,
    temp_min_c    REAL    NOT NULL,
    precip_mm     REAL    NOT NULL,
    wind_max_kmh  REAL    NOT NULL,
    gateway_id    TEXT    NOT NULL,
    received_at   TEXT    NOT NULL,
    stored_at     TEXT    NOT NULL,
    PRIMARY KEY (device_id, date)
);
CREATE INDEX IF NOT EXISTS readings_by_date ON readings (date);
"""


class Storage:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False because uvicorn serves requests on a threadpool.
        # Writes are serialised by the connection lock; single-writer SQLite is a
        # known scaling limit for this baseline.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def store(
        self,
        device_id: str,
        gateway_id: str,
        reading: dict[str, Any],
        received_at: str,
        stored_at: str,
    ) -> str:
        """Insert or update. Returns "stored" or "updated"."""
        existing = self._conn.execute(
            "SELECT 1 FROM readings WHERE device_id = ? AND date = ?",
            (device_id, reading["date"]),
        ).fetchone()

        self._conn.execute(
            """
            INSERT INTO readings
                (device_id, date, temp_max_c, temp_min_c, precip_mm,
                 wind_max_kmh, gateway_id, received_at, stored_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (device_id, date) DO UPDATE SET
                temp_max_c   = excluded.temp_max_c,
                temp_min_c   = excluded.temp_min_c,
                precip_mm    = excluded.precip_mm,
                wind_max_kmh = excluded.wind_max_kmh,
                gateway_id   = excluded.gateway_id,
                received_at  = excluded.received_at,
                stored_at    = excluded.stored_at
            """,
            (
                device_id,
                reading["date"],
                reading["temp_max_c"],
                reading["temp_min_c"],
                reading["precip_mm"],
                reading["wind_max_kmh"],
                gateway_id,
                received_at,
                stored_at,
            ),
        )
        self._conn.commit()
        return "updated" if existing else "stored"

    def list_readings(
        self, limit: int = 100, since: str | None = None, device_id: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("date >= ?")
            params.append(since)
        if device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        # S608 is a false positive here: `where` is assembled only from the
        # hardcoded fragments above ("date >= ?", "device_id = ?"). Every
        # caller-supplied value is bound through a `?` placeholder in `params`,
        # so no untrusted input ever reaches the SQL text.
        rows = self._conn.execute(
            f"SELECT * FROM readings {where} ORDER BY date DESC LIMIT ?",  # noqa: S608  # nosec B608
            params,
        ).fetchall()
        return [dict(row) for row in rows]

    def get_by_date(self, date: str, device_id: str | None = None) -> list[dict[str, Any]]:
        if device_id:
            rows = self._conn.execute(
                "SELECT * FROM readings WHERE date = ? AND device_id = ?", (date, device_id)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM readings WHERE date = ?", (date,)
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self) -> dict[str, Any]:
        row = self._conn.execute(
            """
            SELECT COUNT(*) AS total,
                   COUNT(DISTINCT device_id) AS devices,
                   MIN(date) AS first_date,
                   MAX(date) AS last_date
            FROM readings
            """
        ).fetchone()
        return dict(row)
