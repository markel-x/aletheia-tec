# Aletheia — imagen multi-etapa.
#
#   target "test"    : aplicación + herramientas; ejecuta ruff, mypy y pytest.
#   target "runtime" : sólo dependencias de ejecución, usuario sin privilegios.
#
# Dependencias instaladas con uv desde uv.lock (--frozen: el lock manda; --require-hashes
# lo garantiza uv al exportar). Imagen base: Python 3.13 sobre Debian 13 (trixie), slim.
# En CI/producción fijar además el digest: --build-arg PYTHON_IMAGE=python:3.13.15-slim-trixie@sha256:<digest>
ARG PYTHON_IMAGE=python:3.13.15-slim-trixie
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.21

# ---------------------------------------------------------------------------
FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app/src
# Parches de seguridad de Debian publicados después de la imagen base (p. ej. OpenSSL).
RUN apt-get update \
 && apt-get -y upgrade --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 aletheia \
 && useradd --system --uid 10001 --gid aletheia --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin aletheia \
 && mkdir -p /var/lib/aletheia/dev-keys && chown -R 10001:10001 /var/lib/aletheia
# /var/lib/aletheia/dev-keys: claves PEM del backend local_dev (volumen en compose; vacío en producción).
WORKDIR /app

# ---------------------------------------------------------------------------
FROM base AS runtime-deps
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_NO_CACHE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1
COPY pyproject.toml uv.lock ./
# --no-install-project: sólo dependencias; el código se copia aparte y se importa vía PYTHONPATH.
# --no-binary-package no aplica: se exige wheel para todo (sin compilar dentro de la imagen).
RUN uv sync --frozen --no-dev --no-install-project --no-editable --link-mode=copy \
      --python /usr/local/bin/python3

# ---------------------------------------------------------------------------
FROM runtime-deps AS test
RUN uv sync --frozen --no-install-project --no-editable --link-mode=copy \
      --python /usr/local/bin/python3
COPY src ./src
COPY tests ./tests
# El código queda de root y de sólo lectura para el usuario de ejecución;
# las cachés de las herramientas se desactivan o van a /tmp.
ENV RUFF_NO_CACHE=true \
    MYPY_CACHE_DIR=/tmp/.mypy_cache \
    HOME=/tmp
USER 10001:10001
CMD ["sh", "-c", "ruff check src tests && ruff format --check src tests && mypy && pytest -q -p no:cacheprovider"]

# ---------------------------------------------------------------------------
FROM base AS runtime
LABEL org.opencontainers.image.title="aletheia" \
      org.opencontainers.image.description="Emisión y verificación de credenciales verificables (perfil ALT-P1)" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="Propietario"
COPY --from=runtime-deps /opt/venv /opt/venv
# pip no se usa en ejecución y trae dependencias vendorizadas con CVEs (urllib3, msgpack...).
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
      /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13
COPY src ./src
# Seguro por defecto: fuera de "development" el firmante local se niega a operar.
ENV ALETHEIA_ENV=production
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import sys,urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:8000/readyz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "aletheia"]
CMD ["version"]
