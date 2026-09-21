"""SQLite persistence for received telemetry."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from wire.telemetry import WeatherReading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS readings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id        TEXT    NOT NULL,
    seq               INTEGER NOT NULL,
    suite             TEXT    NOT NULL,
    received_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    date              TEXT    NOT NULL,
    temp_max_c        REAL,
    temp_min_c        REAL,
    precipitation_mm  REAL,
    windspeed_max_kmh REAL,
    UNIQUE (session_id, seq)
);
CREATE INDEX IF NOT EXISTS readings_by_suite ON readings (suite);
"""


class ReadingStore:
    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def insert(self, session_id: str, seq: int, suite: str, reading: WeatherReading) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO readings "
                "(session_id, seq, suite, date, temp_max_c, temp_min_c, "
                " precipitation_mm, windspeed_max_kmh) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    seq,
                    suite,
                    reading.date,
                    reading.temp_max_c,
                    reading.temp_min_c,
                    reading.precipitation_mm,
                    reading.windspeed_max_kmh,
                ),
            )
            self._conn.commit()

    def query(self, limit: int = 50, suite: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM readings"
        params: list[Any] = []
        if suite:
            sql += " WHERE suite = ?"
            params.append(suite)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            return [dict(row) for row in self._conn.execute(sql, params)]

    def counts_by_suite(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute("SELECT suite, COUNT(*) AS n FROM readings GROUP BY suite")
            return {row["suite"]: row["n"] for row in rows}

    def total(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM readings").fetchone()
            return int(row["n"])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
