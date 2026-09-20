"""Gateway protocol and plaintext models."""

from __future__ import annotations

from datetime import date
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IDENTIFIER = r"^[A-Za-z0-9._:-]+$"
MAX_CIPHERTEXT_BYTES = 16 * 1024
MAX_CIPHERTEXT_BASE64_CHARS = ((MAX_CIPHERTEXT_BYTES + 2) // 3) * 4


class Observation(BaseModel):
    """Validated plaintext accepted from Device and forwarded to Cloud."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    observation_id: str = Field(pattern=IDENTIFIER)
    device_id: str = Field(pattern=IDENTIFIER)
    observed_on: date
    latitude: float = Field(ge=-90, le=90, allow_inf_nan=False)
    longitude: float = Field(ge=-180, le=180, allow_inf_nan=False)
    elevation_m: float = Field(allow_inf_nan=False)
    utc_offset_seconds: int = Field(ge=-43_200, le=50_400)
    timezone: str
    timezone_abbreviation: str
    temperature_max_c: float = Field(allow_inf_nan=False)
    temperature_min_c: float = Field(allow_inf_nan=False)
    precipitation_mm: float = Field(ge=0, allow_inf_nan=False)
    wind_speed_max_kmh: float = Field(ge=0, allow_inf_nan=False)

    @field_validator("timezone")
    @classmethod
    def known_timezone(cls, value: str) -> str:
        """Require an installed IANA timezone."""
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise ValueError("unknown timezone") from error
        return value

    @model_validator(mode="after")
    def validate_cross_fields(self) -> Observation:
        """Validate the stable identity and temperature ordering."""
        if self.observation_id != f"{self.device_id}:{self.observed_on.isoformat()}":
            raise ValueError("observation identity mismatch")
        if self.temperature_min_c > self.temperature_max_c:
            raise ValueError("minimum temperature exceeds maximum")
        return self


class DeviceEnvelope(BaseModel):
    """AES-GCM envelope received from the legacy Device."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    device_id: str = Field(pattern=IDENTIFIER)
    key_id: str = Field(pattern=IDENTIFIER)
    observation_id: str = Field(pattern=IDENTIFIER)
    nonce: str = Field(min_length=16, max_length=16)
    ciphertext: str = Field(min_length=24, max_length=MAX_CIPHERTEXT_BASE64_CHARS)


class CloudEnvelope(BaseModel):
    """ML-KEM/AES-GCM envelope sent to Cloud."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    gateway_id: str = Field(pattern=IDENTIFIER)
    kem: Literal["ML-KEM-768"] = "ML-KEM-768"
    kem_key_id: str = Field(pattern=IDENTIFIER)
    observation_id: str = Field(pattern=IDENTIFIER)
    kem_ciphertext: str = Field(min_length=1452, max_length=1452)
    nonce: str = Field(min_length=16, max_length=16)
    ciphertext: str = Field(min_length=24, max_length=MAX_CIPHERTEXT_BASE64_CHARS)


class CloudResult(BaseModel):
    """Successful response returned by Cloud."""

    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(pattern=IDENTIFIER)
    status: Literal["stored", "duplicate"]
