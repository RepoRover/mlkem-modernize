"""Baseline coverage for the legacy suite.

Deliberately thin: this is the v0 system, and its sparse test coverage is one
of the weaknesses the project sets out to fix. Negative-path, known-answer,
and cross-implementation tests arrive with the validation milestone.
"""

import pqcsuite as cs
from pqcwire.telemetry import WeatherReading


def _pair():
    server = cs.LegacyServer(cs.generate_private_key())
    return server, cs.LegacyClient(server.public_key)


def test_legacy_session_round_trips_a_reading():
    server, client = _pair()
    request, client_session = client.open_session()
    server_session = server.accept(request)

    reading = WeatherReading("2024-01-01", 7.4, 3.4, 1.8, 19.7)
    frame = client_session.seal(reading.to_json().encode())
    assert server_session.open(frame).decode() == reading.to_json()


def test_many_frames_survive_one_session():
    server, client = _pair()
    request, client_session = client.open_session()
    server_session = server.accept(request)

    for index in range(25):
        payload = f"reading-{index}".encode()
        assert server_session.open(client_session.seal(payload)) == payload


def test_rsa_public_key_survives_pem_round_trip():
    server, _ = _pair()
    pem = cs.serialize_public_key(server.public_key)
    assert cs.load_public_key(pem).public_numbers() == server.public_key.public_numbers()


def test_keystore_reuses_an_existing_key(tmp_path):
    path = tmp_path / "rsa.pem"
    first = cs.load_or_create_rsa(path)
    assert path.exists()
    assert cs.load_or_create_rsa(path).private_numbers() == first.private_numbers()


def test_keystore_writes_private_keys_unreadable_to_others(tmp_path):
    path = tmp_path / "rsa.pem"
    cs.load_or_create_rsa(path)
    assert path.stat().st_mode & 0o077 == 0
