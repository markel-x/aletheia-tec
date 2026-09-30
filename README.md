# Aletheia

Plataforma SaaS B2B/B2B2C para **emitir, administrar y verificar credenciales digitales verificables**.
Primer caso de uso (configurable): certificados de finalización de cursos.

> Estado: **incremento 2 de 6** — estructura ejecutable: API FastAPI con `/healthz` y `/readyz`,
> configuración por entorno, modelo de datos con migraciones Alembic, logging estructurado, tarea de
> mantenimiento, `uv.lock`, CI y esqueleto de Terraform (ver `docs/incrementos/02.md`).
> Todavía **no** hay endpoints de negocio (organizaciones, emisión, verificación) ni panel.

## Perfil de credenciales (`ALT-P1`)

SD-JWT VC (`dc+sd-jwt`, draft-19, sobre RFC 9901) · ES256 · vinculación `cnf.jwk` + KB-JWT ·
Token Status List (draft-21) · emisor identificado por JWT VC Issuer Metadata · entrega por OID4VCI 1.0
(pre-autorizado + `tx_code`). OID4VP y conformidad HAIP: pendientes. Detalle en
[`docs/01-perfil-interoperabilidad.md`](docs/01-perfil-interoperabilidad.md).

## Documentación

| Documento | Contenido |
|---|---|
| [`docs/00-alcance-y-supuestos.md`](docs/00-alcance-y-supuestos.md) | Inspección del entorno, supuestos, objetivos no funcionales, fuera de alcance |
| [`docs/01-perfil-interoperabilidad.md`](docs/01-perfil-interoperabilidad.md) | Estándares, versiones, formato exacto, algoritmos, claves, estado, privacidad, brechas HAIP |
| [`docs/02-arquitectura.md`](docs/02-arquitectura.md) | Componentes, módulos, secuencias (emisión, verificación, revocación), permisos, AWS |
| [`docs/03-modelo-de-datos.md`](docs/03-modelo-de-datos.md) | Entidades, restricciones, índices, clasificación y retención |
| [`docs/adr/`](docs/adr/) | ADR-0001 a ADR-0011 |
| [`docs/incrementos/01.md`](docs/incrementos/01.md) | Reporte del incremento 1 |
| [`docs/incrementos/02.md`](docs/incrementos/02.md) | Reporte del incremento 2 |

## Estructura

```
src/aletheia/cli.py          CLI: `api`, `migrate`, `maintenance`, `demo`, `version`
src/aletheia/api/            Aplicación FastAPI (fábrica, `/healthz`, `/readyz`)
src/aletheia/platform/       Configuración, sesión de BD, logging JSON, errores estables, request-id
src/aletheia/db/models.py    Modelo ORM (SQLAlchemy 2) — espejo de docs/03
src/aletheia/db/migrations/  Alembic; el DDL inicial vive en `sql/0001_initial_schema.sql`
src/aletheia/maintenance.py  Purga programada de datos caducados (ADR-0008)
src/aletheia/vc/             Núcleo: SD-JWT VC, JWS, firmantes (local dev / AWS KMS), Token Status List, verificador
tests/                       Pruebas: núcleo (tests/vc), plataforma, API, migraciones y mantenimiento (marca `db`)
db/init/                     Inicialización local de PostgreSQL: roles y base de pruebas
db/tests/                    Pruebas SQL del esquema y de privilegios (`docker compose run --rm db-test`)
infra/terraform/             Esqueleto de infraestructura AWS (proveedor, variables, módulos previstos)
.github/workflows/ci.yml     CI: mismas imágenes y comandos que en local
uv.lock, Dockerfile, compose.yaml, .dockerignore, Makefile
docs/                        Alcance, perfil, arquitectura, modelo de datos, ADRs, reportes
```

## Ejecutar con Docker

Requisitos: Docker Engine 24+ con Compose v2 y acceso a Docker Hub y PyPI.

```bash
docker compose build                # imágenes aletheia:test y aletheia:runtime (uv sync --frozen)
docker compose up -d api            # db → migrate → api en http://127.0.0.1:8008
curl -s http://127.0.0.1:8008/readyz
docker compose run --rm tests       # ruff + mypy + pytest (las pruebas de BD usan la base aletheia_test)
docker compose run --rm db-test     # pruebas SQL del esquema, restricciones y privilegios
docker compose run --rm demo        # emisión → verificación → revocación → verificación (sin BD)
docker compose run --rm maintenance # purga de datos caducados
docker run --rm aletheia:runtime    # {"version": "0.1.0", "profile": "ALT-P1"}
```

PostgreSQL queda en `127.0.0.1:5433` (`ALETHEIA_DB_PORT`) con la base `aletheia` y la base de pruebas
`aletheia_test`. Roles: `aletheia_migrate` (propietario; ejecuta `aletheia migrate`) y `aletheia_app`
(la API: DML, y sólo `INSERT/SELECT` en `audit_event`). Contraseñas de desarrollo por defecto,
sobreescribibles con `ALETHEIA_DB_PASSWORD` y `ALETHEIA_APP_PASSWORD`. `docker compose down -v` borra
el volumen. Puertos de host: `ALETHEIA_API_PORT` (8008) y `ALETHEIA_DB_PORT` (5433).

### Configuración (variables `ALETHEIA_*`)

| Variable | Por defecto | Uso |
|---|---|---|
| `ALETHEIA_ENV` | `production` | `development` / `test` habilitan el firmante local y `/docs` |
| `ALETHEIA_DATABASE_URL` | — | `postgresql+psycopg://…`; obligatoria para `api`, `migrate`, `maintenance` |
| `ALETHEIA_PUBLIC_BASE_URL` | `http://localhost:8000` | Origen público (`iss`, URIs de listas de estado) |
| `ALETHEIA_LOG_LEVEL` / `ALETHEIA_LOG_FORMAT` | `INFO` / `json` | Logging estructurado; `text` en local |
| `ALETHEIA_DB_POOL_SIZE`, `..._POOL_TIMEOUT_SECONDS`, `..._STATEMENT_TIMEOUT_MS` | 5 / 5 / 5000 | Pool y límite por sentencia |

Dependencias: `pyproject.toml` + `uv.lock` (versiones exactas y hashes). `make lock` lo regenera con la
misma versión de `uv` que usa la imagen.

`make docker-build`, `make docker-test` y `make docker-demo` son equivalentes. La imagen `runtime`
arranca con `ALETHEIA_ENV=production`; la demostración sólo funciona con `ALETHEIA_ENV=development`
(así lo configura `compose.yaml`). Detalles y decisiones en [ADR-0011](docs/adr/0011-imagen-de-contenedor.md).

## Ejecutar sin Docker

```bash
uv sync --group dev
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy
uv run pytest                                   # las pruebas marcadas `db` se omiten sin PostgreSQL
ALETHEIA_TEST_DATABASE_URL=postgresql+psycopg://aletheia_migrate:dev-migrate-password@127.0.0.1:5433/aletheia_test uv run pytest
ALETHEIA_ENV=development ALETHEIA_DATABASE_URL=postgresql+psycopg://aletheia_app:dev-app-password@127.0.0.1:5433/aletheia uv run aletheia api
```
