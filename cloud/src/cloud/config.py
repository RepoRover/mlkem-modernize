"""Cloud environment configuration."""

import os
from pathlib import Path
from typing import Self

from pydantic import DirectoryPath, Field, FilePath
from pydantic_settings import BaseSettings, SettingsConfigDict

from cloud.models import IDENTIFIER


class Settings(BaseSettings):
    """Validated Cloud runtime settings."""

    model_config = SettingsConfigDict(extra="ignore", case_sensitive=True)

    @classmethod
    def from_environment(cls) -> Self:
        """Validate an environment snapshot using the configured field aliases."""
        return cls.model_validate(dict(os.environ))

    gateway_id: str = Field(validation_alias="GATEWAY_ID", pattern=IDENTIFIER)
    gateway_api_token_file: FilePath = Field(validation_alias="GATEWAY_API_TOKEN_FILE")
    mlkem_private_keys_dir: DirectoryPath = Field(
        validation_alias="MLKEM_PRIVATE_KEYS_DIR"
    )
    database_url_file: FilePath = Field(validation_alias="DATABASE_URL_FILE")
    tls_cert_file: FilePath = Field(validation_alias="TLS_CERT_FILE")
    tls_key_file: FilePath = Field(validation_alias="TLS_KEY_FILE")

    @property
    def key_directory(self) -> Path:
        """Return the key directory as a concrete path."""
        return Path(self.mlkem_private_keys_dir)
