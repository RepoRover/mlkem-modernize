"""Weather telemetry schema and loader for the Open-Meteo archive export.

The dataset ships with a two-line station preamble before the real header, so
the loader scans for the ``time`` column rather than assuming a fixed offset.
Unit suffixes such as ``temperature_2m_max (C)`` are normalised away, keeping
the field names stable if the export is regenerated with different units.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

_COLUMN_ALIASES = {
    "time": "date",
    "temperature_2m_max": "temp_max_c",
    "temperature_2m_min": "temp_min_c",
    "precipitation_sum": "precipitation_mm",
    "windspeed_10m_max": "windspeed_max_kmh",
}


class DatasetError(ValueError):
    """Raised when the telemetry source cannot be parsed."""


@dataclass(frozen=True)
class StationMetadata:
    latitude: float
    longitude: float
    elevation: float
    timezone: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WeatherReading:
    date: str
    temp_max_c: Optional[float]
    temp_min_c: Optional[float]
    precipitation_mm: Optional[float]
    windspeed_max_kmh: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> WeatherReading:
        try:
            return cls(
                date=str(raw["date"]),
                temp_max_c=_opt_float(raw.get("temp_max_c")),
                temp_min_c=_opt_float(raw.get("temp_min_c")),
                precipitation_mm=_opt_float(raw.get("precipitation_mm")),
                windspeed_max_kmh=_opt_float(raw.get("windspeed_max_kmh")),
            )
        except KeyError as exc:
            raise DatasetError("reading is missing field {}".format(exc)) from None


@dataclass(frozen=True)
class WeatherDataset:
    station: StationMetadata
    readings: List[WeatherReading]

    def __len__(self) -> int:
        return len(self.readings)

    def __iter__(self) -> Iterator[WeatherReading]:
        return iter(self.readings)


def _opt_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        raise DatasetError("expected a number, got {!r}".format(value)) from None


def _normalise(column: str) -> str:
    base = column.split(" (")[0].strip()
    return _COLUMN_ALIASES.get(base, base)


def _find_header(rows: Sequence[List[str]]) -> int:
    for index, row in enumerate(rows):
        if row and row[0].strip() == "time":
            return index
    raise DatasetError("no 'time' header row found; is this an Open-Meteo CSV export?")


def _parse_station(rows: Sequence[List[str]], header_index: int) -> StationMetadata:
    if header_index < 2:
        raise DatasetError("station preamble is missing")
    keys = [cell.strip() for cell in rows[0]]
    values = [cell.strip() for cell in rows[1]]
    fields = dict(zip(keys, values))
    try:
        return StationMetadata(
            latitude=float(fields["latitude"]),
            longitude=float(fields["longitude"]),
            elevation=float(fields["elevation"]),
            timezone=fields.get("timezone", "UTC"),
        )
    except (KeyError, ValueError) as exc:
        raise DatasetError("malformed station preamble: {}".format(exc)) from None


def load_dataset(path: Path) -> WeatherDataset:
    with Path(path).open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.reader(handle)]

    header_index = _find_header(rows)
    station = _parse_station(rows, header_index)
    columns = [_normalise(cell) for cell in rows[header_index]]

    readings: List[WeatherReading] = []
    for row in rows[header_index + 1 :]:
        if not row or not row[0].strip():
            continue
        record = dict(zip(columns, row))
        readings.append(WeatherReading.from_dict(record))

    if not readings:
        raise DatasetError("dataset contains no readings")
    return WeatherDataset(station=station, readings=readings)
