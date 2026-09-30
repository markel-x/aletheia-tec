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
| [`docs/adr/`](docs/adr/) | ADR-0001 a ADR-0010 |
| [`docs/incrementos/01.md`](docs/incrementos/01.md) | Reporte del incremento 1 |

## Estructura

```
src/aletheia/vc/        Núcleo: SD-JWT VC, JWS, firmantes (local dev / AWS KMS), Token Status List, verificador
tests/vc/               Pruebas del núcleo (vectores de especificaciones, seguridad, criterios de aceptación)
docs/                   Alcance, perfil, arquitectura, modelo de datos, ADRs, reportes
```

## Ejecutar las pruebas del núcleo

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
