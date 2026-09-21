import pytest

from pqcwire.telemetry import DatasetError, WeatherReading, load_dataset


def test_dataset_loads_with_station_metadata(dataset_path):
    dataset = load_dataset(dataset_path)
    assert len(dataset) == 366  # 2024 is a leap year
    assert dataset.station.timezone == "Europe/Berlin"
    assert 52 < dataset.station.latitude < 53


def test_unit_suffixes_are_stripped_from_column_names(dataset_path):
    first = load_dataset(dataset_path).readings[0]
    assert first.date == "2024-01-01"
    assert first.temp_max_c == 7.4
    assert first.precipitation_mm == 1.8


def test_reading_json_is_deterministic():
    reading = WeatherReading("2024-01-01", 7.4, 3.4, 1.8, 19.7)
    assert reading.to_json() == WeatherReading.from_dict(reading.to_dict()).to_json()


def test_missing_values_become_none():
    reading = WeatherReading.from_dict({"date": "2024-01-01", "temp_max_c": "", "temp_min_c": None})
    assert reading.temp_max_c is None
    assert reading.windspeed_max_kmh is None


def test_rejects_a_csv_without_a_time_header(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b\n1,2\n")
    with pytest.raises(DatasetError, match="time"):
        load_dataset(bad)


def test_rejects_non_numeric_measurements():
    with pytest.raises(DatasetError, match="expected a number"):
        WeatherReading.from_dict({"date": "2024-01-01", "temp_max_c": "warm"})
