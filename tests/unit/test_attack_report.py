import pytest

from scripts.check_attack_report import HYBRID_PQC, LEGACY_RSA, validate


def _reports(mode="modern"):
    backbone_suite = LEGACY_RSA if mode == "baseline" else HYBRID_PQC
    backbone_decrypted = 3 if mode == "baseline" else 0
    return [
        {
            "link": "edge",
            "suites": [LEGACY_RSA],
            "frames_seen": 3,
            "frames_decrypted": 3,
        },
        {
            "link": "backbone",
            "suites": [backbone_suite],
            "frames_seen": 3,
            "frames_decrypted": backbone_decrypted,
        },
    ]


def _cloud(mode="modern"):
    suite = LEGACY_RSA if mode == "baseline" else HYBRID_PQC
    return {"total": 3, "by_suite": {suite: 3}}


@pytest.mark.parametrize("mode", ["baseline", "modern"])
def test_complete_migration_evidence_passes(mode):
    assert validate(mode, _reports(mode), _cloud(mode)) == []


def test_empty_capture_fails():
    reports = _reports()
    reports[1]["frames_seen"] = 0
    assert any("nonzero" in failure for failure in validate("modern", reports, _cloud()))


def test_wrong_suite_fails():
    reports = _reports()
    reports[1]["suites"] = [LEGACY_RSA]
    assert any(
        "expected only suite" in failure for failure in validate("modern", reports, _cloud())
    )


def test_partial_decryption_fails():
    reports = _reports("baseline")
    reports[0]["frames_decrypted"] = 2
    assert any(
        "expected 3/3" in failure for failure in validate("baseline", reports, _cloud("baseline"))
    )


def test_empty_cloud_storage_fails():
    failures = validate("modern", _reports(), {"total": 0, "by_suite": {HYBRID_PQC: 0}})
    assert any("stored reading" in failure for failure in failures)


def test_missing_expected_link_fails():
    assert any("no traffic" in failure for failure in validate("modern", _reports()[:1], _cloud()))
