"""The parser must cope with the two-block Open-Meteo export, and validation
must reject implausible readings."""

from __future__ import annotations

import pytest

from services.common.weather import (
    ValidationError,
    WeatherDataError,
    iter_readings,
    parse_weather_file,
    parse_weather_text,
    validate_reading,
)

from .conftest import DATA_FILE

SAMPLE = """latitude,longitude,elevation,utc_offset_seconds,timezone,timezone_abbreviation
52.54833,13.407822,38.0,7200,Europe/Berlin,GMT+2

time,temperature_2m_max (°C),temperature_2m_min (°C),precipitation_sum (mm),windspeed_10m_max (km/h)
2024-01-01,7.4,3.4,1.80,19.7
2024-01-02,7.0,2.5,7.20,20.2
"""


def test_parses_the_two_block_format():
    station, readings = parse_weather_text(SAMPLE)

    assert station.lat == pytest.approx(52.54833)
    assert station.lon == pytest.approx(13.407822)
    assert station.tz == "Europe/Berlin"

    assert len(readings) == 2
    assert readings[0].date == "2024-01-01"
    assert readings[0].temp_max_c == pytest.approx(7.4)
    assert readings[0].wind_max_kmh == pytest.approx(19.7)


def test_parses_the_real_dataset():
    station, readings = parse_weather_file(DATA_FILE)

    # 2024 is a leap year and the export has no gaps.
    assert len(readings) == 366
    assert readings[0].date == "2024-01-01"
    assert readings[-1].date == "2024-12-31"
    assert station.tz == "Europe/Berlin"
    # Every record should already satisfy our own validation rules.
    for reading in readings:
        validate_reading(reading.to_dict())


def test_single_block_file_is_rejected():
    with pytest.raises(WeatherDataError, match="blank line"):
        parse_weather_text("time,temperature_2m_max\n2024-01-01,7.4\n")


def test_truncated_record_row_is_rejected():
    truncated = SAMPLE.replace("2024-01-02,7.0,2.5,7.20,20.2", "2024-01-02,7.0,2.5")
    with pytest.raises(WeatherDataError, match="fields, expected"):
        parse_weather_text(truncated)


def test_missing_column_is_rejected():
    without_wind = SAMPLE.replace(",windspeed_10m_max (km/h)", "").replace(
        ",19.7", ""
    ).replace(",20.2", "")
    with pytest.raises(WeatherDataError, match="missing column"):
        parse_weather_text(without_wind)


def test_empty_record_block_is_rejected():
    """A header with no data rows is a silently-broken export, not an empty result."""
    header_only = (
        "latitude,longitude,elevation,utc_offset_seconds,timezone,timezone_abbreviation\n"
        "52.54833,13.407822,38.0,7200,Europe/Berlin,GMT+2\n"
        "\n"
        "time,temperature_2m_max (°C),temperature_2m_min (°C),"
        "precipitation_sum (mm),windspeed_10m_max (km/h)\n"
    )
    with pytest.raises(WeatherDataError, match="no readings"):
        parse_weather_text(header_only)


def test_station_row_shorter_than_its_header_is_rejected():
    broken = SAMPLE.replace(
        "52.54833,13.407822,38.0,7200,Europe/Berlin,GMT+2", "52.54833,13.407822"
    )
    with pytest.raises(WeatherDataError, match="fewer fields"):
        parse_weather_text(broken)


def test_station_block_missing_a_column_is_rejected():
    broken = SAMPLE.replace("latitude,longitude,elevation", "lat,longitude,elevation")
    with pytest.raises(WeatherDataError, match="missing column"):
        parse_weather_text(broken)


def test_station_block_with_a_non_numeric_value_is_rejected():
    broken = SAMPLE.replace("52.54833,13.407822", "north,13.407822")
    with pytest.raises(WeatherDataError, match="non-numeric"):
        parse_weather_text(broken)


def test_record_row_with_an_empty_field_is_rejected():
    """Open-Meteo emits an empty cell for a missing observation."""
    broken = SAMPLE.replace("2024-01-02,7.0,2.5,7.20,20.2", "2024-01-02,7.0,,7.20,20.2")
    with pytest.raises(WeatherDataError, match="empty field"):
        parse_weather_text(broken)


def test_record_row_with_a_bad_date_is_rejected():
    broken = SAMPLE.replace("2024-01-02,", "2024-13-45,")
    with pytest.raises(WeatherDataError, match="bad date"):
        parse_weather_text(broken)


def test_record_row_with_a_non_numeric_measurement_is_rejected():
    broken = SAMPLE.replace("2024-01-02,7.0,2.5", "2024-01-02,warm,2.5")
    with pytest.raises(WeatherDataError, match="non-numeric measurement"):
        parse_weather_text(broken)


def test_error_messages_name_the_offending_row():
    """A 366-row file needs the row number to be debuggable."""
    broken = SAMPLE.replace("2024-01-02,7.0,2.5,7.20,20.2", "2024-01-02,7.0,2.5")
    with pytest.raises(WeatherDataError, match="row 3"):
        parse_weather_text(broken)


def test_iter_readings_stops_when_not_looping():
    _, readings = parse_weather_text(SAMPLE)
    assert [r.date for r in iter_readings(readings, loop=False)] == [
        "2024-01-01",
        "2024-01-02",
    ]


def test_iter_readings_wraps_around_when_looping():
    """The device replays the same year indefinitely."""
    _, readings = parse_weather_text(SAMPLE)
    stream = iter_readings(readings, loop=True)
    dates = [next(stream).date for _ in range(5)]
    assert dates == ["2024-01-01", "2024-01-02", "2024-01-01", "2024-01-02", "2024-01-01"]


def test_parse_weather_file_reads_utf8_regardless_of_platform_default(tmp_path):
    """The headers contain a degree sign; a cp1252 default would corrupt them."""
    path = tmp_path / "wx.csv"
    path.write_text(SAMPLE, encoding="utf-8")

    station, readings = parse_weather_file(path)
    assert station.tz == "Europe/Berlin"
    assert len(readings) == 2


def _good() -> dict:
    return {
        "date": "2024-01-01",
        "temp_max_c": 7.4,
        "temp_min_c": 3.4,
        "precip_mm": 1.8,
        "wind_max_kmh": 19.7,
    }


def test_valid_reading_passes():
    assert validate_reading(_good()).date == "2024-01-01"


@pytest.mark.parametrize(
    "mutation, message",
    [
        ({"temp_max_c": 500.0}, "outside"),
        ({"temp_min_c": -200.0}, "outside"),
        ({"precip_mm": -1.0}, "outside"),
        ({"wind_max_kmh": -5.0}, "outside"),
        ({"temp_min_c": 30.0, "temp_max_c": 10.0}, "greater than"),
        ({"date": "not-a-date"}, "ISO 8601"),
        ({"temp_max_c": "7.4"}, "not a number"),
        ({"temp_max_c": True}, "not a number"),
    ],
)
def test_implausible_readings_are_rejected(mutation, message):
    payload = {**_good(), **mutation}
    with pytest.raises(ValidationError, match=message):
        validate_reading(payload)


def test_missing_field_is_rejected():
    payload = _good()
    del payload["precip_mm"]
    with pytest.raises(ValidationError, match="missing field: precip_mm"):
        validate_reading(payload)
