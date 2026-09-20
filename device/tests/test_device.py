import base64
from datetime import date
from pathlib import Path

import pytest
from crypto import device_aad, encrypt_observation
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dataset import load_dataset, observations_for_cycle
from delivery import DeliveryAction, classify_response, retry_delay
from errors import DeviceError
from models import Location, Observation
from pydantic import ValidationError


@pytest.fixture
def location() -> Location:
    return Location(
        latitude=52.54833,
        longitude=13.407822,
        elevation_m=38,
        utc_offset_seconds=7200,
        timezone="Europe/Berlin",
        timezone_abbreviation="GMT+2",
    )


def observation(location: Location) -> Observation:
    return Observation(
        observation_id="weather-station-001:2024-01-01",
        device_id="weather-station-001",
        observed_on=date(2024, 1, 1),
        temperature_max_c=7.4,
        temperature_min_c=3.4,
        precipitation_mm=1.8,
        wind_speed_max_kmh=19.7,
        **location.model_dump(),
    )


def write_csv(path: Path, rows: str) -> Path:
    path.write_text(
        "latitude,longitude,elevation,utc_offset_seconds,timezone,timezone_abbreviation\n"
        "52.54833,13.407822,38.0,7200,Europe/Berlin,GMT+2\n\n"
        "time,temperature_2m_max (°C),temperature_2m_min (°C),precipitation_sum (mm),windspeed_10m_max (km/h)\n"
        + rows,
        encoding="utf-8",
    )
    return path


def test_load_dataset_and_skip_bad_row(tmp_path: Path) -> None:
    path = write_csv(
        tmp_path / "weather.csv",
        "2024-01-01,7.4,3.4,1.8,19.7\n"
        "2024-01-02,bad,2.5,7.2,20.2\n"
        "2024-01-03,10.6,7.3,12.1,27.8\n",
    )

    parsed_location, rows = load_dataset(path)

    assert parsed_location.timezone == "Europe/Berlin"
    assert [row.observed_on for row in rows] == [date(2024, 1, 1), date(2024, 1, 3)]


def test_load_dataset_rejects_invalid_structure_and_empty_data(tmp_path: Path) -> None:
    empty = write_csv(tmp_path / "empty.csv", "")
    with pytest.raises(DeviceError, match="no valid observations"):
        load_dataset(empty)

    invalid = tmp_path / "invalid.csv"
    invalid.write_text("wrong,header\n1,2\n\nwrong,daily\n", encoding="utf-8")
    with pytest.raises(DeviceError, match="headers"):
        load_dataset(invalid)


def test_calendar_cycles_skip_invalid_leap_day(
    location: Location, tmp_path: Path
) -> None:
    _, sources = load_dataset(
        write_csv(
            tmp_path / "leap.csv",
            "2024-02-28,5,1,0,10\n2024-02-29,6,2,0,11\n2024-03-01,7,3,0,12\n",
        )
    )

    cycle_zero = list(observations_for_cycle("device-1", location, sources, 0))
    cycle_one = list(observations_for_cycle("device-1", location, sources, 1))

    assert [item.observed_on for item in cycle_zero] == [
        date(2024, 2, 28),
        date(2024, 2, 29),
        date(2024, 3, 1),
    ]
    assert [item.observed_on for item in cycle_one] == [
        date(2025, 2, 28),
        date(2025, 3, 1),
    ]
    assert cycle_one[0].observation_id == "device-1:2025-02-28"


def test_observation_cross_field_validation(location: Location) -> None:
    values = observation(location).model_dump()
    values["observation_id"] = "weather-station-001:2024-01-02"
    with pytest.raises(ValidationError):
        Observation.model_validate(values)

    values = observation(location).model_dump()
    values["unexpected"] = True
    with pytest.raises(ValidationError):
        Observation.model_validate(values)


def test_device_envelope_round_trip_and_authenticated_fields(
    location: Location,
) -> None:
    item = observation(location)
    key = bytes(range(32))
    envelope = encrypt_observation(item, "device-key-001", key)
    nonce = base64.b64decode(envelope.nonce, validate=True)
    ciphertext = base64.b64decode(envelope.ciphertext, validate=True)
    aad = device_aad(item.device_id, envelope.key_id, item.observation_id)

    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    assert Observation.model_validate_json(plaintext) == item
    assert len(nonce) == 12

    changed_fields = [
        device_aad(item.device_id, envelope.key_id, item.observation_id, 2),
        device_aad("other-device", envelope.key_id, item.observation_id),
        device_aad(item.device_id, "other-key", item.observation_id),
        device_aad(item.device_id, envelope.key_id, "other-observation"),
    ]
    for changed_aad in changed_fields:
        with pytest.raises(InvalidTag):
            AESGCM(key).decrypt(nonce, ciphertext, changed_aad)


def test_gateway_response_classification() -> None:
    observation_id = "device-1:2024-01-01"
    accepted = {"observation_id": observation_id, "status": "stored"}

    assert classify_response(201, accepted, observation_id) is DeliveryAction.ACCEPT
    assert classify_response(408, None, observation_id) is DeliveryAction.RETRY
    assert classify_response(429, None, observation_id) is DeliveryAction.RETRY
    assert classify_response(503, None, observation_id) is DeliveryAction.RETRY
    assert classify_response(502, None, observation_id) is DeliveryAction.RETRY
    assert (
        classify_response(502, {"status": "upstream_rejected"}, observation_id)
        is DeliveryAction.FATAL
    )
    assert classify_response(401, None, observation_id) is DeliveryAction.FATAL
    assert classify_response(422, None, observation_id) is DeliveryAction.SKIP
    assert classify_response(201, {}, observation_id) is DeliveryAction.FATAL


def test_retry_delay_is_exponential_capped_and_jittered() -> None:
    assert retry_delay(1, 4, 1, sample=0) == 0.5
    assert retry_delay(1, 4, 3, sample=1) == 4
    assert retry_delay(1, 4, 10_000, sample=1) == 4
