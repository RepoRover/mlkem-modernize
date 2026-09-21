"""The attacker must succeed against the legacy suite, and only with the key."""

import cryptosuite as cs
from services.harvester.attack import harvest
from wire.telemetry import WeatherReading

READINGS = [
    WeatherReading("2024-01-01", 7.4, 3.4, 1.8, 19.7),
    WeatherReading("2024-01-02", 7.0, 2.5, 7.2, 20.2),
    WeatherReading("2024-01-03", 10.6, 7.3, 12.1, 27.8),
]


def _capture(link: str = "edge"):
    """Produce a capture of one legacy session carrying three readings."""
    private_key = cs.generate_private_key()
    server = cs.LegacyServer(private_key)
    client = cs.LegacyClient(server.public_key)
    request, session = client.open_session()

    entries = [
        {"link": link, "path": "/legacy/session", "request_json": request.to_dict()}
    ]
    for reading in READINGS:
        frame = session.seal(reading.to_json().encode())
        entries.append(
            {"link": link, "path": "/legacy/frames", "request_json": frame.to_dict()}
        )
    return entries, private_key


def test_recovered_key_decrypts_every_archived_frame():
    entries, private_key = _capture()
    (report,) = harvest(entries, [private_key])

    assert report.compromised
    assert report.sessions_recovered == 1
    assert report.frames_decrypted == len(READINGS)
    assert report.decryption_rate == 1.0
    assert '"date":"2024-01-01"' in report.samples[0]


def test_captured_traffic_stays_opaque_without_the_key():
    entries, _ = _capture()
    (report,) = harvest(entries, [])

    assert not report.compromised
    assert report.sessions_recovered == 0
    assert report.frames_decrypted == 0
    assert report.frames_seen == len(READINGS)
    assert any("no matching RSA private key" in note for note in report.notes)


def test_the_wrong_key_does_not_help():
    entries, _ = _capture()
    (report,) = harvest(entries, [cs.generate_private_key()])

    assert not report.compromised
    assert report.frames_decrypted == 0


def test_each_link_is_reported_separately():
    edge, edge_key = _capture("edge")
    backbone, backbone_key = _capture("backbone")
    reports = harvest(edge + backbone, [edge_key, backbone_key])

    assert [report.link for report in reports] == ["backbone", "edge"]
    assert all(report.frames_decrypted == len(READINGS) for report in reports)
