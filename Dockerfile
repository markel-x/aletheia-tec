# Aletheia — imagen multi-etapa.
#
#   target "test"    : núcleo + herramientas; ejecuta ruff, mypy y pytest.
#   target "runtime" : sólo dependencias de ejecución, usuario sin privilegios.
#
# Imagen base: Python 3.13 sobre Debian 13 (trixie), variante slim.
# En CI/producción fijar además el digest: --build-arg PYTHON_IMAGE=python:3.13.15-slim-trixie@sha256:<digest>
ARG PYTHON_IMAGE=python:3.13.15-slim-trixie

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app/src
RUN groupadd --system --gid 10001 aletheia \
 && useradd --system --uid 10001 --gid aletheia --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin aletheia
WORKDIR /app

# ---------------------------------------------------------------------------
FROM base AS runtime-deps
COPY requirements/runtime.txt /tmp/requirements/runtime.txt
# --no-deps + lista completa y fijada: cualquier transitiva no declarada rompe el build.
# --only-binary: sin compilación de código nativo dentro de la imagen.
RUN python -m venv "$VIRTUAL_ENV" \
 && pip install --no-deps --only-binary=:all: -r /tmp/requirements/runtime.txt \
 && pip check

# ---------------------------------------------------------------------------
FROM runtime-deps AS test
COPY requirements/dev.txt /tmp/requirements/dev.txt
RUN pip install --no-deps --only-binary=:all: -r /tmp/requirements/dev.txt \
 && pip check
COPY pyproject.toml ./
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
COPY src ./src
# Seguro por defecto: fuera de "development" el firmante local se niega a operar.
ENV ALETHEIA_ENV=production
USER 10001:10001
ENTRYPOINT ["python", "-m", "aletheia"]
CMD ["version"]
