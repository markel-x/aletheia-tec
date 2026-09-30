# Aletheia

Plataforma SaaS B2B/B2B2C para **emitir, administrar y verificar credenciales digitales verificables**.
Primer caso de uso (configurable): certificados de finalización de cursos.

> Estado: **incremento 1 de 6** — alcance, perfil de interoperabilidad, arquitectura y núcleo criptográfico probado.
> La API, la persistencia, el panel y Terraform todavía **no** existen (ver `docs/incrementos/01.md`).

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

## Estructura

```
src/aletheia/cli.py     CLI: `aletheia demo`, `aletheia version`
src/aletheia/vc/        Núcleo: SD-JWT VC, JWS, firmantes (local dev / AWS KMS), Token Status List, verificador
tests/vc/               Pruebas del núcleo (vectores de especificaciones, seguridad, criterios de aceptación)
requirements/           Dependencias fijadas para las imágenes (runtime, dev)
Dockerfile, compose.yaml, .dockerignore, Makefile
docs/                   Alcance, perfil, arquitectura, modelo de datos, ADRs, reportes
```

## Ejecutar con Docker

Requisitos: Docker Engine 24+ con Compose v2 y acceso a Docker Hub y PyPI.

```bash
docker compose build                # imágenes aletheia:test y aletheia:runtime
docker compose run --rm tests       # ruff + mypy + pytest dentro del contenedor
docker compose run --rm demo        # emisión → verificación → revocación → verificación
docker run --rm aletheia:runtime    # {"version": "0.1.0", "profile": "ALT-P1"}
```

`make docker-build`, `make docker-test` y `make docker-demo` son equivalentes. La imagen `runtime`
arranca con `ALETHEIA_ENV=production`; la demostración sólo funciona con `ALETHEIA_ENV=development`
(así lo configura `compose.yaml`). Detalles y decisiones en [ADR-0011](docs/adr/0011-imagen-de-contenedor.md).

## Ejecutar las pruebas del núcleo sin Docker

Con acceso a PyPI (entorno normal):

```bash
uv sync --group dev
uv run pytest
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy
```

El núcleo sólo necesita `cryptography` y `PyJWT`; si están instalados en el Python del sistema:

```bash
PYTHONPATH=src python3 -m pytest -q tests/vc
```
