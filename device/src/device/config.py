"""Device environment configuration."""

from __future__ import annotations

import os
from typing import Self

from pydantic import AnyHttpUrl, Field, FilePath, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from device.models import IDENTIFIER


class Settings(BaseSettings):
    """Validated Device environment settings."""

    model_config = SettingsConfigDict(extra="ignore", case_sensitive=True)

    @classmethod
    def from_environment(cls) -> Self:
        """Validate an environment snapshot using the configured field aliases."""
        return cls.model_validate(dict(os.environ))

    device_id: str = Field(validation_alias="DEVICE_ID", pattern=IDENTIFIER)
    device_key_id: str = Field(validation_alias="DEVICE_KEY_ID", pattern=IDENTIFIER)
    device_key_file: FilePath = Field(validation_alias="DEVICE_KEY_FILE")
    gateway_url: AnyHttpUrl = Field(validation_alias="GATEWAY_URL")
    gateway_timeout_seconds: float = Field(
        default=35,
        validation_alias="GATEWAY_TIMEOUT_SECONDS",
        gt=0,
        allow_inf_nan=False,
    )
    ca_cert_file: FilePath = Field(validation_alias="CA_CERT_FILE")
    weather_csv_file: FilePath = Field(validation_alias="WEATHER_CSV_FILE")
    send_interval_seconds: float = Field(
        validation_alias="SEND_INTERVAL_SECONDS", ge=0, allow_inf_nan=False
    )
    retry_initial_seconds: float = Field(
        validation_alias="RETRY_INITIAL_SECONDS", gt=0, allow_inf_nan=False
    )
    retry_max_seconds: float = Field(
        validation_alias="RETRY_MAX_SECONDS", gt=0, allow_inf_nan=False
    )
    max_cycles: int | None = Field(default=None, validation_alias="MAX_CYCLES", gt=0)

    @field_validator("gateway_url")
    @classmethod
    def require_https(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        """Reject an unencrypted Gateway endpoint."""
        if value.scheme != "https":
            raise ValueError("GATEWAY_URL must use HTTPS")
        return value

    @model_validator(mode="after")
    def validate_retry_range(self) -> Settings:
        """Keep the configured initial retry delay within its cap."""
        if self.retry_initial_seconds > self.retry_max_seconds:
            raise ValueError("RETRY_INITIAL_SECONDS must not exceed RETRY_MAX_SECONDS")
        return self
