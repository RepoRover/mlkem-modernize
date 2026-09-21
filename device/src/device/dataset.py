"""Weather CSV parsing and calendar-cycle transformation."""

import csv
import logging
from collections.abc import Iterator
from pathlib import Path

from pydantic import ValidationError

from device.errors import DeviceError, validation_codes
from device.models import Location, Observation, SourceObservation

logger = logging.getLogger("device")
METADATA_HEADER = [
    "latitude",
    "longitude",
    "elevation",
    "utc_offset_seconds",
    "timezone",
    "timezone_abbreviation",
]
DAILY_HEADER = [
    "time",
    "temperature_2m_max (°C)",
    "temperature_2m_min (°C)",
    "precipitation_sum (mm)",
    "windspeed_10m_max (km/h)",
]


def load_dataset(path: Path) -> tuple[Location, list[SourceObservation]]:
    """Parse and validate the two-section weather CSV.

    Malformed daily rows are logged and omitted. Structural or metadata errors
    fail the complete load before any delivery starts.
    """
    try:
        file = path.open(encoding="utf-8", newline="")
    except OSError as error:
        raise DeviceError("weather CSV could not be read") from error

    with file:
        reader = csv.reader(file)
        try:
            metadata_header = next(reader)
            metadata_values = next(reader)
            separator = next(reader)
            daily_header = next(reader)
        except StopIteration as error:
            raise DeviceError("weather CSV structure is incomplete") from error

        if (
            len(metadata_header) != len(METADATA_HEADER)
            or set(metadata_header) != set(METADATA_HEADER)
            or len(daily_header) != len(DAILY_HEADER)
            or set(daily_header) != set(DAILY_HEADER)
            or separator
        ):
            raise DeviceError("weather CSV headers or section separator are invalid")
        if len(metadata_values) != len(METADATA_HEADER):
            raise DeviceError("weather CSV location row is invalid")

        metadata = dict(zip(metadata_header, metadata_values, strict=True))
        try:
            location = Location.model_validate(
                {
                    "latitude": metadata["latitude"],
                    "longitude": metadata["longitude"],
                    "elevation_m": metadata["elevation"],
                    "utc_offset_seconds": metadata["utc_offset_seconds"],
                    "timezone": metadata["timezone"],
                    "timezone_abbreviation": metadata["timezone_abbreviation"],
                }
            )
        except ValidationError as error:
            logger.error(
                "event=csv_metadata_rejected errors=%s", validation_codes(error)
            )
            raise DeviceError("weather CSV location metadata is invalid") from error

        observations: list[SourceObservation] = []
        for row in reader:
            line_number = reader.line_num
            try:
                if len(row) != len(DAILY_HEADER):
                    raise ValueError
                daily = dict(zip(daily_header, row, strict=True))
                observations.append(
                    SourceObservation.model_validate(
                        {
                            "observed_on": daily["time"],
                            "temperature_max_c": daily["temperature_2m_max (°C)"],
                            "temperature_min_c": daily["temperature_2m_min (°C)"],
                            "precipitation_mm": daily["precipitation_sum (mm)"],
                            "wind_speed_max_kmh": daily["windspeed_10m_max (km/h)"],
                        }
                    )
                )
            except ValidationError, ValueError:
                logger.warning("event=csv_row_skipped line=%d", line_number)

    if not observations:
        raise DeviceError("weather CSV contains no valid observations")
    return location, observations


def observations_for_cycle(
    device_id: str,
    location: Location,
    sources: list[SourceObservation],
    cycle: int,
) -> Iterator[Observation]:
    """Create observations shifted by ``cycle`` calendar years."""
    for source in sources:
        target_year = source.observed_on.year + cycle
        if target_year > 9999:
            logger.error("event=calendar_range_exhausted cycle=%d", cycle)
            raise DeviceError("calendar range exhausted")
        try:
            observed_on = source.observed_on.replace(year=target_year)
        except ValueError:
            logger.info(
                "event=calendar_day_skipped source_date=%s cycle=%d",
                source.observed_on.isoformat(),
                cycle,
            )
            continue
        yield Observation(
            observation_id=f"{device_id}:{observed_on.isoformat()}",
            device_id=device_id,
            observed_on=observed_on,
            **location.model_dump(),
            **source.model_dump(exclude={"observed_on"}),
        )
