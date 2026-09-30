"""Resolución de claves y obtención de listas de estado para el verificador.

- Emisores **alojados** (``{base}/issuers/{org}``): claves y listas desde la
  base de datos, sin red (revocación inmediata, doc 00 §4).
- Emisores **externos**: HTTPS con límites (timeout, tamaño, sin redirecciones)
  y caché en proceso. Sólo se consultan si la política ya los declara
  confiables: el verificador comprueba la confianza antes de resolver.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import models
from ..organizations.keys import SignerBackend
from ..platform.config import Settings
from ..status import service as status
from ..vc.verifier import (
    DependencyUnavailable,
    FetchedStatusList,
    KeyNotFound,
    KeyState,
    ResolvedKey,
)

log = logging.getLogger(__name__)

HTTP_TIMEOUT = 5.0
MAX_METADATA_BYTES = 64 * 1024
MAX_STATUS_LIST_BYTES = 1024 * 1024
CACHE_TTL = 300


@dataclass(frozen=True)
class _Cached:
    value: Any
    at: int


class _Cache:
    def __init__(self) -> None:
        self._data: dict[str, _Cached] = {}
        self._lock = threading.Lock()

    def get(self, key: str, now: int) -> Any | None:
        with self._lock:
            hit = self._data.get(key)
        return hit.value if hit and now - hit.at < CACHE_TTL else None

    def put(self, key: str, value: Any, now: int) -> None:
        with self._lock:
            self._data[key] = _Cached(value, now)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


_metadata_cache = _Cache()
_status_cache = _Cache()


def clear_caches() -> None:
    _metadata_cache.clear()
    _status_cache.clear()


def _fetch(url: str, max_bytes: int, accept: str) -> bytes:
    if urlsplit(url).scheme != "https":
        raise DependencyUnavailable("only https is allowed")
    try:
        with (
            httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False) as client,
            client.stream("GET", url, headers={"Accept": accept}) as response,
        ):
            if response.status_code != 200:
                raise DependencyUnavailable(f"HTTP {response.status_code}")
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise DependencyUnavailable("response too large")
            return bytes(body)
    except httpx.HTTPError as exc:
        raise DependencyUnavailable(f"network error: {exc.__class__.__name__}") from exc


def hosted_org_public_id(settings: Settings, issuer: str) -> str | None:
    prefix = f"{settings.public_base}/issuers/"
    if issuer.startswith(prefix):
        rest = issuer[len(prefix) :]
        if rest and "/" not in rest:
            return rest
    return None


class KeyResolver:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    def resolve(self, issuer: str, kid: str) -> ResolvedKey:
        org_public_id = hosted_org_public_id(self._settings, issuer)
        if org_public_id is not None:
            return self._resolve_hosted(org_public_id, kid)
        return self._resolve_external(issuer, kid)

    def _resolve_hosted(self, org_public_id: str, kid: str) -> ResolvedKey:
        key = self._session.scalar(
            select(models.SigningKey)
            .join(models.Organization, models.Organization.id == models.SigningKey.organization_id)
            .where(models.Organization.public_id == org_public_id)
            .where(models.SigningKey.kid == kid)
        )
        if key is None:
            raise KeyNotFound(kid)
        return ResolvedKey(key.public_jwk, KeyState(key.state))

    def _resolve_external(self, issuer: str, kid: str) -> ResolvedKey:
        now = int(time.time())
        keys = _metadata_cache.get(issuer, now)
        if keys is None:
            parts = urlsplit(issuer)
            if parts.scheme != "https" or parts.query or parts.fragment:
                raise DependencyUnavailable("issuer must be a plain https URL")
            url = f"https://{parts.netloc}/.well-known/jwt-vc-issuer{parts.path.rstrip('/')}"
            body = _fetch(url, MAX_METADATA_BYTES, "application/json")
            try:
                metadata = json.loads(body)
            except ValueError as exc:
                raise DependencyUnavailable("issuer metadata is not JSON") from exc
            if not isinstance(metadata, dict) or metadata.get("issuer") != issuer:
                raise DependencyUnavailable("issuer metadata does not match the issuer")
            jwks = metadata.get("jwks")
            if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
                # jwks_uri (indirecto) no se sigue en el MVP: una URL más que controla el emisor.
                raise DependencyUnavailable("issuer metadata without inline jwks")
            keys = [k for k in jwks["keys"] if isinstance(k, dict)]
            _metadata_cache.put(issuer, keys, now)
        for key in keys:
            if key.get("kid") == kid:
                return ResolvedKey(key, KeyState.ACTIVE)
        raise KeyNotFound(kid)


class StatusFetcher:
    def __init__(self, session: Session, settings: Settings, backend: SignerBackend) -> None:
        self._session = session
        self._settings = settings
        self._backend = backend

    def fetch(self, uri: str) -> FetchedStatusList:
        now = int(time.time())
        prefix = f"{self._settings.public_base}/status-lists/"
        if uri.startswith(prefix) and "/" not in uri[len(prefix) :]:
            signed = status.signed_token(
                self._session, self._backend, self._settings, uri[len(prefix) :], now
            )
            return FetchedStatusList(token=signed.token, fetched_at=now)
        cached = _status_cache.get(uri, now)
        if cached is not None:
            return FetchedStatusList(token=cached[0], fetched_at=cached[1])
        body = _fetch(uri, MAX_STATUS_LIST_BYTES, "application/statuslist+jwt")
        try:
            token = body.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise DependencyUnavailable("status list is not a JWT") from exc
        _status_cache.put(uri, (token, now), now)
        return FetchedStatusList(token=token, fetched_at=now)
