"""Configuración por entorno.

Todo proviene de variables de entorno con prefijo ``ALETHEIA_`` (en ECS las
inyecta la definición de tarea; en local, ``compose.yaml``). No se leen
archivos ``.env`` automáticamente: evita que un archivo olvidado cambie el
comportamiento de una imagen.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, HttpUrl, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def is_deployed(self) -> bool:
        return self in (Environment.STAGING, Environment.PRODUCTION)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ALETHEIA_", frozen=True, extra="ignore")

    env: Environment = Environment.PRODUCTION
    """Seguro por defecto: fuera de ``development``/``test`` no hay firmante local."""

    database_url: PostgresDsn | None = None
    """DSN de psycopg 3 (``postgresql+psycopg://``). Obligatoria para ``api``/``migrate``."""

    public_base_url: HttpUrl = HttpUrl("http://localhost:8000")
    """Origen público (``iss`` de los emisores alojados, URIs de listas de estado)."""

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "text"] = "json"

    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_pool_timeout_seconds: int = Field(default=5, ge=1, le=60)
    db_statement_timeout_ms: int = Field(default=5_000, ge=100, le=60_000)

    signing_backend: Literal["local_dev", "aws_kms"] = "aws_kms"
    """``local_dev`` sólo en ``development``/``test`` (ADR-0006)."""

    dev_keys_dir: Path = Path("/var/lib/aletheia/dev-keys")
    """Directorio de claves PEM del backend ``local_dev`` (fuera del repositorio)."""

    aws_region: str | None = None
    """Región para el cliente KMS; si es ``None`` se usa la configuración de boto3."""

    @field_validator("database_url")
    @classmethod
    def _psycopg_driver(cls, value: PostgresDsn | None) -> PostgresDsn | None:
        if value is not None and value.scheme != "postgresql+psycopg":
            raise ValueError("ALETHEIA_DATABASE_URL debe usar el esquema postgresql+psycopg://")
        return value

    @property
    def public_base(self) -> str:
        return str(self.public_base_url).rstrip("/")

    def require_database_url(self) -> str:
        if self.database_url is None:
            raise RuntimeError("ALETHEIA_DATABASE_URL no está definida")
        return str(self.database_url)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
