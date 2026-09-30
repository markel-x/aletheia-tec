# Aletheia

Plataforma SaaS B2B/B2B2C para **emitir, administrar y verificar credenciales digitales verificables**.
Primer caso de uso (configurable): certificados de finalización de cursos.

> Estado: **incremento 5 de 6** — verificación por API (políticas de confianza, solicitudes de
> presentación, `/v1/verifications` con emisores alojados y externos), panel administrativo en
> `/admin`, `Authorize` en Swagger (ver `docs/incrementos/05.md`). Pendiente: despliegue en AWS
> (Terraform), prueba con wallet real, RLS.

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
| [`docs/incrementos/03.md`](docs/incrementos/03.md) | Reporte del incremento 3 |
| [`docs/incrementos/04.md`](docs/incrementos/04.md) | Reporte del incremento 4 |
| [`docs/incrementos/05.md`](docs/incrementos/05.md) | Reporte del incremento 5 |

## Estructura

```
src/aletheia/cli.py          CLI: `api`, `migrate`, `maintenance`, `bootstrap`, `demo`, `version`
src/aletheia/api/            Aplicación FastAPI (fábrica, dependencias, `/healthz`, `/readyz`)
src/aletheia/platform/       Configuración, sesión de BD, logging JSON, errores, request-id, ids, rate limit
src/aletheia/authz/          Matriz de permisos, login/sesiones, claves de API, `/v1/auth`, `/v1/api-clients`
src/aletheia/organizations/  Alta, miembros, perfil de emisor, claves de firma (local/KMS), `/.well-known/jwt-vc-issuer`
src/aletheia/audit/          Registro append-only de acciones sensibles
src/aletheia/issuance/       Plantillas, esquema de claims, ofertas, OID4VCI, emisión, revocación
src/aletheia/status/         Asignación de índices y Token Status List (`/status-lists/{id}`)
src/aletheia/usage/          Consumo por organización (`/v1/usage`)
src/aletheia/verification/   Políticas de confianza, solicitudes de presentación, verificaciones, resolvers
src/aletheia/admin/          Panel estático (`/admin`): HTML + módulos ES, sin build, CSP estricta
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

### Panel y documentación interactiva

- Panel: **http://127.0.0.1:8008/admin/** (inicie sesión con el correo y la contraseña del propietario).
- Swagger UI: **http://127.0.0.1:8008/docs** (botón *Authorize* → pegue el token `st_…` o una clave `ak_…`).

### Primera organización y uso de la API

```bash
docker compose run --rm -e ALETHEIA_BOOTSTRAP_PASSWORD='una contraseña larga' bootstrap \
  --name "Universidad Demo" --owner-email owner@example.org --owner-name "Propietaria"
curl -s -X POST http://127.0.0.1:8008/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"owner@example.org","password":"una contraseña larga"}'      # → {"token": "st_…", …}
curl -s http://127.0.0.1:8008/v1/organization -H "Authorization: Bearer st_…"
curl -s http://127.0.0.1:8008/.well-known/jwt-vc-issuer/issuers/org_…        # JWKS público del emisor
```

| Endpoint | Permiso |
|---|---|
| `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/auth/me` | — / sesión |
| `GET /v1/organization`, `GET /v1/organization/issuer-profile` | cualquier miembro |
| `PUT /v1/organization/issuer-profile`, `GET /v1/signing-keys`, `POST /v1/signing-keys/rotate` | `org:manage` |
| `POST /v1/signing-keys/{id}/compromise` | `signing_keys:compromise` (sólo owner) |
| `GET/POST /v1/members`, `PATCH/DELETE /v1/members/{user_id}` | `members:manage` |
| `GET/POST /v1/api-clients`, `DELETE /v1/api-clients/{id}` | `api_clients:manage` |
| `GET /v1/audit-events` | `audit:read` |
| `GET /v1/usage` | `usage:read` |
| `GET /v1/templates`, `GET /v1/templates/{id}/versions` | `templates:read` |
| `POST /v1/templates`, `POST /v1/templates/{id}/versions`, `POST …/versions/{vid}/publish` | `templates:write` |
| `POST /v1/credentials` (oferta; `Idempotency-Key`), `POST /v1/credentials/{id}/offer:reset` | `credentials:issue` |
| `GET /v1/credentials`, `GET /v1/credentials/{id}` | `credentials:read` |
| `POST /v1/credentials/{id}/revoke` | `credentials:revoke` |
| `GET /.well-known/jwt-vc-issuer/issuers/{org_public_id}` | público |
| `GET /.well-known/openid-credential-issuer/issuers/{org}`, `GET /.well-known/oauth-authorization-server/issuers/{org}` | público |
| `GET /oid4vci/offers/{offer_id}`, `POST /oid4vci/token`, `POST /oid4vci/nonce`, `POST /oid4vci/credential` | wallet (OID4VCI) |
| `GET /status-lists/{public_id}` | público, cacheable (`ttl` 300 s) |
| `GET /v1/trust-policies`, `GET /v1/trust-policies/{id}`, `POST /v1/presentation-requests`, `POST/GET /v1/verifications` | `verifications:create` |
| `POST /v1/trust-policies`, `POST/DELETE /v1/trust-policies/{id}/issuers[/{tid}]` | `trust_policies:write` |

Flujo de verificación: `POST /v1/presentation-requests` devuelve `nonce` y `aud` (10 min, un uso); el
titular presenta `SD-JWT~disclosures~KB-JWT` con ese `aud`/`nonce`; `POST /v1/verifications` ejecuta
las 11 comprobaciones del núcleo (claves y estado de emisores alojados desde la base; externos por
HTTPS con límites y caché) y devuelve `valid` / `invalid` / `indeterminate` con el detalle y los
claims divulgados. Se registra el resultado, nunca los claims.

Flujo de emisión: `POST /v1/credentials` devuelve `offer_uri` (para QR/enlace), `qr_svg` y `tx_code`
(**una sola vez**; se envía al titular por otro canal). El wallet resuelve la oferta, canjea el código
pre-autorizado con el `tx_code` en `/oid4vci/token`, pide un `c_nonce`, y presenta un proof JWT con su
clave en `/oid4vci/credential`; recibe el SD-JWT VC y Aletheia borra los claims pendientes.

Las claves de API (`ak_…`) van en `Authorization: Bearer` igual que las sesiones y sólo pueden tener un
subconjunto de los permisos de quien las crea (nunca `members:manage` ni `signing_keys:compromise`).

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
| `ALETHEIA_SIGNING_BACKEND` | `aws_kms` | `local_dev` sólo en `development`/`test` (ADR-0006) |
| `ALETHEIA_DEV_KEYS_DIR` | `/var/lib/aletheia/dev-keys` | Claves PEM del backend local (volumen `dev-keys` en compose) |
| `ALETHEIA_AWS_REGION` | — | Región del cliente KMS |
| `ALETHEIA_KMS_DATA_KEY_ID` | — | Clave KMS simétrica para cifrar claims pendientes (obligatoria con `aws_kms`) |
| `ALETHEIA_OID4VCI_ACCESS_TOKEN_TTL_SECONDS`, `..._NONCE_TTL_SECONDS`, `ALETHEIA_TX_CODE_MAX_ATTEMPTS` | 300 / 300 / 5 | Parámetros del flujo OID4VCI |

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
