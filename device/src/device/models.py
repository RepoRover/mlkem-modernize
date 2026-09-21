"""Device protocol and weather models."""

from __future__ import annotations

from datetime import date
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IDENTIFIER = r"^[A-Za-z0-9._:-]+$"


class Location(BaseModel):
    """Location metadata shared by every source observation."""

    model_config = ConfigDict(extra="forbid")

    latitude: float = Field(ge=-90, le=90, allow_inf_nan=False)
    longitude: float = Field(ge=-180, le=180, allow_inf_nan=False)
    elevation_m: float = Field(allow_inf_nan=False)
    utc_offset_seconds: int = Field(ge=-43_200, le=50_400)
    timezone: str
    timezone_abbreviation: str

    @field_validator("timezone")
    @classmethod
    def known_timezone(cls, value: str) -> str:
        """Require an installed IANA timezone."""
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise ValueError("unknown timezone") from error
        return value


class SourceObservation(BaseModel):
    """One validated daily row before its calendar-cycle shift."""

    model_config = ConfigDict(extra="forbid")

    observed_on: date
    temperature_max_c: float = Field(allow_inf_nan=False)
    temperature_min_c: float = Field(allow_inf_nan=False)
    precipitation_mm: float = Field(ge=0, allow_inf_nan=False)
    wind_speed_max_kmh: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_temperature_range(self) -> SourceObservation:
        """Reject impossible min/max ordering."""
        if self.temperature_min_c > self.temperature_max_c:
            raise ValueError("minimum temperature exceeds maximum")
        return self


class Observation(Location):
    """Validated plaintext sent over both encrypted application hops."""

    schema_version: int = Field(default=1, frozen=True)
    observation_id: str = Field(pattern=IDENTIFIER)
    device_id: str = Field(pattern=IDENTIFIER)
    observed_on: date
    temperature_max_c: float = Field(allow_inf_nan=False)
    temperature_min_c: float = Field(allow_inf_nan=False)
    precipitation_mm: float = Field(ge=0, allow_inf_nan=False)
    wind_speed_max_kmh: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_cross_fields(self) -> Observation:
        """Validate the stable identity and temperature ordering."""
        if self.schema_version != 1:
            raise ValueError("unsupported schema version")
        if self.observation_id != f"{self.device_id}:{self.observed_on.isoformat()}":
            raise ValueError("observation identity mismatch")
        if self.temperature_min_c > self.temperature_max_c:
            raise ValueError("minimum temperature exceeds maximum")
        return self


class DeviceEnvelope(BaseModel):
    """AES-GCM envelope accepted by Gateway."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, frozen=True)
    device_id: str = Field(pattern=IDENTIFIER)
    key_id: str = Field(pattern=IDENTIFIER)
    observation_id: str = Field(pattern=IDENTIFIER)
    nonce: str
    ciphertext: str
