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

from pydantic import Field, HttpUrl, PostgresDsn, SecretStr, field_validator
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

    database_password: SecretStr | None = None
    """Si se define, reemplaza la contraseña del DSN (ECS inyecta secretos como valores
    sueltos desde Secrets Manager; el DSN queda sin secretos en la definición de tarea)."""

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

    kms_data_key_id: str | None = None
    """Clave KMS simétrica para el cifrado envelope de claims pendientes (backend ``aws_kms``)."""

    oid4vci_access_token_ttl_seconds: int = Field(default=300, ge=60, le=900)
    oid4vci_nonce_ttl_seconds: int = Field(default=300, ge=60, le=900)
    tx_code_max_attempts: int = Field(default=5, ge=1, le=10)
    oid4vci_token_rate_limit: int = Field(default=60, ge=1)
    """Canjes por red (/24, /64) cada 15 min en ``/oid4vci/token``."""

    tx_code_key: SecretStr | None = None
    """Clave HMAC (≥ 32 bytes, base64url) de los ``tx_code``. Obligatoria en entornos
    desplegados (Secrets Manager); en desarrollo se genera en ``dev_keys_dir``."""
    """Canjes por red (/24, /64) cada 15 min en ``/oid4vci/token``."""

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
        if self.database_password is None:
            return str(self.database_url)
        from sqlalchemy.engine import make_url

        url = make_url(str(self.database_url)).set(
            password=self.database_password.get_secret_value()
        )
        return url.render_as_string(hide_password=False)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
