"""Logging estructurado.

- Formato JSON por línea (CloudWatch lo indexa) o texto en desarrollo.
- ``request_id`` propagado por ``contextvars`` desde el middleware.
- Los campos cuyo nombre sugiere secretos o datos personales se redactan
  antes de emitirse: es una red de seguridad, no sustituye a no registrarlos.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

_SENSITIVE_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "authorization",
    "cookie",
    "tx_code",
    "private",
    "email",
    "given_name",
    "family_name",
    "claims",
)
_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "taskName",
    "color_message",  # duplicado con códigos ANSI que añade uvicorn
}


def is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in _SENSITIVE_FRAGMENTS)


def redact(value: Any) -> Any:
    """Redacta recursivamente claves sensibles en dicts/listas."""
    if isinstance(value, dict):
        return {k: "[redacted]" if is_sensitive(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if request_id := request_id_var.get():
            payload["request_id"] = request_id
        extras = {k: v for k, v in record.__dict__.items() if k not in _STANDARD_ATTRS}
        payload.update(redact(extras))
        if record.exc_info:
            payload["exc_type"] = getattr(record.exc_info[0], "__name__", "Exception")
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        request_id = request_id_var.get()
        prefix = f"[{request_id}] " if request_id else ""
        extras = {k: v for k, v in record.__dict__.items() if k not in _STANDARD_ATTRS}
        suffix = f" {json.dumps(redact(extras), ensure_ascii=False, default=str)}" if extras else ""
        base = f"{record.levelname:8} {prefix}{record.name}: {record.getMessage()}{suffix}"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # uvicorn escribe su propio access log; lo sustituye el middleware de la app.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers[:] = []
        logging.getLogger(name).propagate = name != "uvicorn.access"
