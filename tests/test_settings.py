"""Settings factories validate real environment sources without bypassing models."""

from pathlib import Path

import pytest
from cloud.config import Settings as CloudSettings
from device.config import Settings as DeviceSettings
from gateway.config import Settings as GatewaySettings
from pydantic import ValidationError

from tools.bootstrap import generate


@pytest.mark.parametrize(
    ("settings_type", "identity_variable", "file_variable"),
    [
        (DeviceSettings, "DEVICE_ID", "DEVICE_KEY_FILE"),
        (GatewaySettings, "GATEWAY_ID", "MLKEM_PUBLIC_KEY_FILE"),
        (CloudSettings, "GATEWAY_ID", "DATABASE_URL_FILE"),
    ],
)
def test_environment_factory_validates_required_fields(
    settings_type: type[DeviceSettings | GatewaySettings | CloudSettings],
    identity_variable: str,
    file_variable: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generate(tmp_path)
    environment = {
        "DEVICE_ID": "device-1",
        "DEVICE_KEY_ID": "key-1",
        "DEVICE_KEY_FILE": str(tmp_path / "device.key"),
        "GATEWAY_URL": "https://gateway/v1/observations",
        "CA_CERT_FILE": str(tmp_path / "ca/ca.crt"),
        "WEATHER_CSV_FILE": str(
            Path(__file__).resolve().parents[1] / "device/data/weather_data.csv"
        ),
        "SEND_INTERVAL_SECONDS": "1",
        "RETRY_INITIAL_SECONDS": "0.25",
        "RETRY_MAX_SECONDS": "2",
        "GATEWAY_ID": "gateway-1",
        "CLOUD_URL": "https://cloud/v1/observations",
        "CLOUD_CA_CERT_FILE": str(tmp_path / "ca/ca.crt"),
        "CLOUD_API_TOKEN_FILE": str(tmp_path / "gateway.token"),
        "MLKEM_KEY_ID": "cloud-kem-001",
        "MLKEM_PUBLIC_KEY_FILE": str(tmp_path / "public/cloud-kem-001.pub"),
        "TLS_CERT_FILE": str(tmp_path / "gateway/tls.crt"),
        "TLS_KEY_FILE": str(tmp_path / "gateway/tls.key"),
        "GATEWAY_API_TOKEN_FILE": str(tmp_path / "gateway.token"),
        "MLKEM_PRIVATE_KEYS_DIR": str(tmp_path / "active"),
        "DATABASE_URL_FILE": str(tmp_path / "database.url"),
    }
    for field in settings_type.model_fields.values():
        assert isinstance(field.validation_alias, str)
        monkeypatch.delenv(field.validation_alias, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    settings = settings_type.from_environment()
    assert isinstance(settings, settings_type)
    if isinstance(settings, DeviceSettings):
        assert settings.device_key_file == tmp_path / "device.key"
        assert settings.gateway_timeout_seconds == 35
    elif isinstance(settings, GatewaySettings):
        assert settings.cloud_forward_deadline_seconds == 30
    else:
        assert settings.key_directory == tmp_path / "active"

    monkeypatch.delenv(identity_variable)
    with pytest.raises(ValidationError) as missing:
        settings_type.from_environment()
    assert any(error["type"] == "missing" for error in missing.value.errors())

    monkeypatch.setenv(identity_variable, "invalid identity")
    with pytest.raises(ValidationError) as invalid:
        settings_type.from_environment()
    assert any(
        error["type"] == "string_pattern_mismatch" for error in invalid.value.errors()
    )

    monkeypatch.setenv(identity_variable, environment[identity_variable])
    monkeypatch.setenv(file_variable, str(tmp_path / "does-not-exist"))
    with pytest.raises(ValidationError):
        settings_type.from_environment()
