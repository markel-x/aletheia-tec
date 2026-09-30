# ADR-0011 · Imagen de contenedor

- Estado: Aceptada · 2026-09-30

## Decisión
- Base: `python:3.13.15-slim-trixie` (imagen oficial, Debian 13, variante slim). Python 3.13 tiene soporte de correcciones y de seguridad por más tiempo que 3.12. En CI y producción se fija además el **digest** (`--build-arg PYTHON_IMAGE=…@sha256:…`) y se actualiza con Dependabot/Renovate.
- Un solo `Dockerfile` multi-etapa:
  - `runtime-deps`: venv en `/opt/venv` con `requirements/runtime.txt` (versiones exactas, `--no-deps`, `--only-binary=:all:`, `pip check`).
  - `test`: añade `requirements/dev.txt`, código y pruebas; ejecuta ruff, mypy y pytest.
  - `runtime`: sólo venv de ejecución + `src/`; sin compiladores, sin pip en el `PATH` de trabajo, sin pruebas.
- Usuario sin privilegios `10001:10001`; código propiedad de root (no modificable en ejecución).
- `ALETHEIA_ENV=production` por defecto en `runtime`: el firmante local se niega a operar salvo que se indique `development` explícitamente.
- `compose.yaml` aplica `read_only`, `tmpfs /tmp` (modo 1777), `cap_drop: ALL`, `no-new-privileges`, `init` y `network_mode: none` (el núcleo no usa red). En ECS se replican con `readonlyRootFilesystem`, sin capacidades y usuario no root.
- `.dockerignore` en modo lista blanca: el contexto sólo incluye `pyproject.toml`, `requirements/`, `src/` y `tests/` (nunca `.env`, `.dev-keys/`, `.git`).

## Pendiente (incremento 2)
- Reemplazar `requirements/*.txt` por `uv.lock` con hashes (`--require-hashes`).
- Servicios `api` (con `HEALTHCHECK` sobre `/readyz`), `migrate` y `db` (PostgreSQL 16).
- Escaneo de la imagen en ECR y SBOM.

## Validación realizada
Docker Hub y PyPI están bloqueados en el entorno de desarrollo, así que no se pudo construir con la base oficial. Se construyó el mismo Dockerfile sustituyendo **sólo** la imagen base (un rootfs con el Python 3.11 del host) y los dos pasos `pip install` (copiando los mismos paquetes y versiones). Con esa sustitución se comprobó: build de ambas etapas con `docker compose build`; `docker compose run --rm tests` → ruff y mypy sin hallazgos, `107 passed`; `docker compose run --rm demo` → válida antes y `credential_revoked` después de revocar; `runtime` sin `ALETHEIA_ENV=development` rechaza el firmante local (código 2); usuario `uid=10001`; sistema de archivos de sólo lectura; sin red. La prueba reveló que `tmpfs` sin `mode=1777` impedía escribir al usuario no root (corregido).

**No validado:** la imagen base oficial, Python 3.13 dentro del contenedor, la instalación desde PyPI con `--only-binary` (disponibilidad de wheels cp313 para todas las dependencias fijadas).
