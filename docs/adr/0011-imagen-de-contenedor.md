# ADR-0011 · Imagen de contenedor

- Estado: Aceptada · 2026-09-30

## Decisión
- Base: `python:3.13.15-slim-trixie` (imagen oficial, Debian 13, variante slim). Python 3.13 tiene soporte de correcciones y de seguridad por más tiempo que 3.12. En CI y producción se fija además el **digest** (`--build-arg PYTHON_IMAGE=…@sha256:…`) y se actualiza con Dependabot/Renovate.
- Un solo `Dockerfile` multi-etapa:
  - `runtime-deps`: venv en `/opt/venv` creado por `uv sync --frozen --no-dev` desde `uv.lock` (versiones exactas con hashes; `uv` copiado desde su imagen oficial fijada, `ghcr.io/astral-sh/uv:0.12.21`). Sin descarga de intérpretes (`UV_PYTHON_DOWNLOADS=never`).
  - `test`: añade el grupo `dev`, código y pruebas; ejecuta ruff, mypy y pytest.
  - `runtime`: sólo venv de ejecución + `src/`; sin compiladores, sin `uv` ni `pip`, sin pruebas. `HEALTHCHECK` sobre `/readyz`.
- Usuario sin privilegios `10001:10001`; código propiedad de root (no modificable en ejecución).
- `ALETHEIA_ENV=production` por defecto en `runtime`: el firmante local se niega a operar salvo que se indique `development` explícitamente.
- `compose.yaml` aplica `read_only`, `tmpfs /tmp` (modo 1777), `cap_drop: ALL`, `no-new-privileges` e `init` a todos los servicios de la aplicación; `demo` además corre con `network_mode: none`. `db` (PostgreSQL 16) conserva sólo las capacidades que exige el entrypoint oficial. En ECS se replican con `readonlyRootFilesystem`, sin capacidades y usuario no root.
- `.dockerignore` en modo lista blanca: el contexto sólo incluye `pyproject.toml`, `uv.lock`, `src/` y `tests/` (nunca `.env`, `.dev-keys/`, `.git`).
- Una sola imagen, tres roles por comando (ADR-0001): `api`, `migrate` (rol propietario de la BD) y `maintenance`. Los servicios de compose encadenan `db` (healthcheck) → `migrate` (`service_completed_successfully`) → `api`.

## Actualización (incremento 6)
- La etapa `base` aplica `apt-get upgrade` (parches de seguridad de Debian publicados después de la
  imagen base; p. ej. OpenSSL).
- La etapa `runtime` **elimina `pip`**: no se usa en ejecución y trae dependencias vendorizadas con CVEs
  (`urllib3`, `msgpack`, `setuptools`).
- Resultado: Trivy sin vulnerabilidades HIGH/CRITICAL corregibles en `aletheia:runtime`; CI lo exige y
  genera un SBOM CycloneDX. El pipeline de despliegue exige además el escaneo de ECR sin CRITICAL.

## Pendiente
- Escaneo de la imagen en ECR y SBOM (con la infraestructura).
- Fijar el digest de `python:3.13.15-slim-trixie` y de la imagen de `uv` en CI.

## Validación realizada
**Incremento 2 (2026-09-30):** con acceso a Docker Hub, GHCR y PyPI se construyeron ambas etapas con la base oficial (`python:3.13.15-slim-trixie`, Python 3.13.15 dentro del contenedor) y `uv sync --frozen`; `runtime` pasa de 169 MB (sólo núcleo) a 285 MB con la pila web, psycopg y boto3 (`test`: 447 MB). Quedan validadas las tres cosas marcadas como "no validado" abajo.

**Incremento 1:** Docker Hub y PyPI estaban bloqueados en el entorno de desarrollo, así que no se pudo construir con la base oficial. Se construyó el mismo Dockerfile sustituyendo **sólo** la imagen base (un rootfs con el Python 3.11 del host) y los dos pasos `pip install` (copiando los mismos paquetes y versiones). Con esa sustitución se comprobó: build de ambas etapas con `docker compose build`; `docker compose run --rm tests` → ruff y mypy sin hallazgos, `107 passed`; `docker compose run --rm demo` → válida antes y `credential_revoked` después de revocar; `runtime` sin `ALETHEIA_ENV=development` rechaza el firmante local (código 2); usuario `uid=10001`; sistema de archivos de sólo lectura; sin red. La prueba reveló que `tmpfs` sin `mode=1777` impedía escribir al usuario no root (corregido).

**No validado:** la imagen base oficial, Python 3.13 dentro del contenedor, la instalación desde PyPI con `--only-binary` (disponibilidad de wheels cp313 para todas las dependencias fijadas).
