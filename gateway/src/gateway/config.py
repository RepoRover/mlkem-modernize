"""Gateway environment configuration."""

from __future__ import annotations

from pydantic import AnyHttpUrl, Field, FilePath, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from gateway.models import IDENTIFIER


class Settings(BaseSettings):
    """Validated Gateway environment settings."""

    model_config = SettingsConfigDict(extra="ignore", case_sensitive=True)

    device_id: str = Field(validation_alias="DEVICE_ID", pattern=IDENTIFIER)
    device_key_id: str = Field(validation_alias="DEVICE_KEY_ID", pattern=IDENTIFIER)
    device_key_file: FilePath = Field(validation_alias="DEVICE_KEY_FILE")
    gateway_id: str = Field(validation_alias="GATEWAY_ID", pattern=IDENTIFIER)
    cloud_url: AnyHttpUrl = Field(validation_alias="CLOUD_URL")
    cloud_ca_cert_file: FilePath = Field(validation_alias="CLOUD_CA_CERT_FILE")
    cloud_api_token_file: FilePath = Field(validation_alias="CLOUD_API_TOKEN_FILE")
    mlkem_key_id: str = Field(validation_alias="MLKEM_KEY_ID", pattern=IDENTIFIER)
    mlkem_public_key_file: FilePath = Field(validation_alias="MLKEM_PUBLIC_KEY_FILE")
    tls_cert_file: FilePath = Field(validation_alias="TLS_CERT_FILE")
    tls_key_file: FilePath = Field(validation_alias="TLS_KEY_FILE")
    cloud_retry_attempts: int = Field(
        default=3, validation_alias="CLOUD_RETRY_ATTEMPTS", ge=1, le=10
    )
    cloud_timeout_seconds: float = Field(
        default=8,
        validation_alias="CLOUD_TIMEOUT_SECONDS",
        gt=0,
        allow_inf_nan=False,
    )
    cloud_forward_deadline_seconds: float = Field(
        default=30,
        validation_alias="CLOUD_FORWARD_DEADLINE_SECONDS",
        gt=0,
        allow_inf_nan=False,
    )
    cloud_retry_initial_seconds: float = Field(
        default=0.25,
        validation_alias="CLOUD_RETRY_INITIAL_SECONDS",
        ge=0,
        allow_inf_nan=False,
    )
    cloud_retry_max_seconds: float = Field(
        default=2,
        validation_alias="CLOUD_RETRY_MAX_SECONDS",
        ge=0,
        allow_inf_nan=False,
    )

    @field_validator("cloud_url")
    @classmethod
    def require_https(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        """Reject an unencrypted Cloud endpoint."""
        if value.scheme != "https":
            raise ValueError("CLOUD_URL must use HTTPS")
        return value

    @model_validator(mode="after")
    def validate_retry_range(self) -> Settings:
        """Keep retry timing internally consistent."""
        if self.cloud_retry_initial_seconds > self.cloud_retry_max_seconds:
            raise ValueError(
                "CLOUD_RETRY_INITIAL_SECONDS must not exceed CLOUD_RETRY_MAX_SECONDS"
            )
        return self
