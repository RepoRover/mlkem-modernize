"""Parsing and validation of the Open-Meteo daily export in data/.

The file is NOT a plain CSV. It is two CSV blocks separated by a blank line:

    latitude,longitude,elevation,utc_offset_seconds,timezone,timezone_abbreviation
    52.54833,13.407822,38.0,7200,Europe/Berlin,GMT+2
                                                     <- blank line
    time,temperature_2m_max (°C),...
    2024-01-01,7.4,3.4,1.80,19.7
    ...

Handing the whole file to csv.DictReader gives nonsense, so we split explicitly.
Column names carry their units and non-ASCII degree signs, so the file must be
read as UTF-8 rather than whatever the platform default happens to be.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import date as date_type
from io import StringIO
from pathlib import Path
from typing import Any, Iterator

# Plausibility bounds for terrestrial daily weather. These are sanity checks,
# not science: the aim is to reject garbage and obvious tampering, not to
# second-guess the meteorologists.
TEMP_MIN_C = -90.0  # coldest reliably recorded surface temperature
TEMP_MAX_C = 60.0  # hottest
PRECIP_MAX_MM = 2000.0  # daily record is ~1825 mm
WIND_MAX_KMH = 500.0  # tornado-scale upper bound


class WeatherDataError(Exception):
    """The source file does not have the structure we expect."""


class ValidationError(Exception):
    """A reading is structurally fine but not plausible."""


@dataclass(frozen=True)
class Station:
    lat: float
    lon: float
    elev_m: float
    tz: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Reading:
    date: str  # ISO 8601 calendar date, e.g. "2024-01-01"
    temp_max_c: float
    temp_min_c: float
    precip_mm: float
    wind_max_kmh: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Map the unit-bearing source headers onto our field names. Matching on a
# prefix keeps us working if the export's unit suffix changes.
_COLUMN_PREFIXES = {
    "time": "date",
    "temperature_2m_max": "temp_max_c",
    "temperature_2m_min": "temp_min_c",
    "precipitation_sum": "precip_mm",
    "windspeed_10m_max": "wind_max_kmh",
}


def _map_header(header: list[str]) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for index, column in enumerate(header):
        name = column.strip()
        for prefix, field in _COLUMN_PREFIXES.items():
            if name == prefix or name.startswith(prefix + " "):
                mapping[index] = field
                break
    missing = set(_COLUMN_PREFIXES.values()) - set(mapping.values())
    if missing:
        raise WeatherDataError(f"record block is missing column(s): {sorted(missing)}")
    return mapping


def parse_weather_file(path: str | Path) -> tuple[Station, list[Reading]]:
    """Read the two-block export and return the station plus every reading."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_weather_text(text)


def parse_weather_text(text: str) -> tuple[Station, list[Reading]]:
    rows = list(csv.reader(StringIO(text)))

    # A "blank line" comes back from csv.reader as [] or as a row of empty strings.
    def is_blank(row: list[str]) -> bool:
        return not any(cell.strip() for cell in row)

    blocks: list[list[list[str]]] = []
    current: list[list[str]] = []
    for row in rows:
        if is_blank(row):
            if current:
                blocks.append(current)
                current = []
            continue
        current.append(row)
    if current:
        blocks.append(current)

    if len(blocks) < 2:
        raise WeatherDataError(
            f"expected a station block and a record block separated by a blank line, "
            f"found {len(blocks)} block(s)"
        )

    station = _parse_station(blocks[0])
    readings = _parse_records(blocks[1])
    if not readings:
        raise WeatherDataError("record block contains no readings")
    return station, readings


def _parse_station(block: list[list[str]]) -> Station:
    if len(block) < 2:
        raise WeatherDataError("station block needs a header row and a value row")
    header = [c.strip() for c in block[0]]
    values = block[1]
    if len(values) < len(header):
        raise WeatherDataError("station value row has fewer fields than its header")
    row = dict(zip(header, values))
    try:
        return Station(
            lat=float(row["latitude"]),
            lon=float(row["longitude"]),
            elev_m=float(row["elevation"]),
            tz=row["timezone"].strip(),
        )
    except KeyError as exc:
        raise WeatherDataError(f"station block is missing column {exc}") from exc
    except ValueError as exc:
        raise WeatherDataError(f"station block has a non-numeric value: {exc}") from exc


def _parse_records(block: list[list[str]]) -> list[Reading]:
    mapping = _map_header(block[0])
    width = len(block[0])

    readings: list[Reading] = []
    for line_no, row in enumerate(block[1:], start=2):
        if len(row) != width:
            raise WeatherDataError(
                f"record row {line_no} has {len(row)} fields, expected {width}"
            )
        fields: dict[str, str] = {}
        for index, field in mapping.items():
            fields[field] = row[index].strip()

        if any(value == "" for value in fields.values()):
            raise WeatherDataError(f"record row {line_no} has an empty field")

        try:
            date_type.fromisoformat(fields["date"])
        except ValueError as exc:
            raise WeatherDataError(f"record row {line_no} has a bad date: {exc}") from exc

        try:
            readings.append(
                Reading(
                    date=fields["date"],
                    temp_max_c=float(fields["temp_max_c"]),
                    temp_min_c=float(fields["temp_min_c"]),
                    precip_mm=float(fields["precip_mm"]),
                    wind_max_kmh=float(fields["wind_max_kmh"]),
                )
            )
        except ValueError as exc:
            raise WeatherDataError(
                f"record row {line_no} has a non-numeric measurement: {exc}"
            ) from exc

    return readings


def iter_readings(readings: list[Reading], loop: bool) -> Iterator[Reading]:
    """Yield readings once, or forever if `loop` is set."""
    while True:
        for reading in readings:
            yield reading
        if not loop:
            return


# --------------------------------------------------------------------------
# validation (applied at the gateway and again at the cloud)
# --------------------------------------------------------------------------


def validate_reading(payload: dict[str, Any]) -> Reading:
    """Check an untrusted decrypted payload and return it as a Reading.

    Raises ValidationError with a reason safe to log -- it names the field but
    never echoes the full payload, so plaintext does not leak into logs.
    """
    required = ("date", "temp_max_c", "temp_min_c", "precip_mm", "wind_max_kmh")
    for field in required:
        if field not in payload:
            raise ValidationError(f"missing field: {field}")

    if not isinstance(payload["date"], str):
        raise ValidationError("field 'date' is not a string")
    try:
        date_type.fromisoformat(payload["date"])
    except ValueError:
        raise ValidationError("field 'date' is not an ISO 8601 date") from None

    numbers: dict[str, float] = {}
    for field in required[1:]:
        value = payload[field]
        # bool is a subclass of int; reject it so True does not become 1.0.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationError(f"field '{field}' is not a number")
        numbers[field] = float(value)

    for field in ("temp_max_c", "temp_min_c"):
        if not TEMP_MIN_C <= numbers[field] <= TEMP_MAX_C:
            raise ValidationError(f"field '{field}' outside [{TEMP_MIN_C}, {TEMP_MAX_C}]")

    if numbers["temp_min_c"] > numbers["temp_max_c"]:
        raise ValidationError("temp_min_c is greater than temp_max_c")

    if not 0.0 <= numbers["precip_mm"] <= PRECIP_MAX_MM:
        raise ValidationError(f"field 'precip_mm' outside [0, {PRECIP_MAX_MM}]")

    if not 0.0 <= numbers["wind_max_kmh"] <= WIND_MAX_KMH:
        raise ValidationError(f"field 'wind_max_kmh' outside [0, {WIND_MAX_KMH}]")

    return Reading(
        date=payload["date"],
        temp_max_c=numbers["temp_max_c"],
        temp_min_c=numbers["temp_min_c"],
        precip_mm=numbers["precip_mm"],
        wind_max_kmh=numbers["wind_max_kmh"],
    )
