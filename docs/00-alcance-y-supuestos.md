# 00 · Alcance, supuestos y restricciones

Estado: incremento 1 · Fecha: 2026-09-30

## 1. Inspección inicial

| Elemento | Hallazgo | Consecuencia |
|---|---|---|
| Repositorio | No existía repositorio ni documentación previa. Se creó `aletheia/` desde cero. | No hay stack heredado; rige el stack obligatorio (Python + Terraform/AWS). |
| Proyecto de Claude "Aletheia" | Sin documentos. | Sin restricciones adicionales. |
| Python | 3.11.15 disponible (también 3.12 y 3.13). | Código compatible con ≥ 3.11; imagen de contenedor en 3.13 (ADR-0011). |
| Paquetes presentes | `cryptography` 46.0.7, `PyJWT` 2.12.1, `pydantic` 2.13, `starlette` 1.0, `httpx`, `uvicorn`; herramientas `pytest` 9.0.3, `ruff` 0.15.11, `mypy`. | El núcleo criptográfico se puede probar aquí. |
| Paquetes ausentes | FastAPI, SQLAlchemy, Alembic, psycopg, boto3, moto. | **Bloqueante para los incrementos 2–6 en este entorno** (ver §5). |
| Registros de paquetes | PyPI, npm, GitHub, registry.terraform.io y releases.hashicorp.com responden 403 (política de salida de red). | No se pueden instalar dependencias ni Terraform aquí. |
| PostgreSQL | Binarios de PostgreSQL 16 presentes (`initdb`, `pg_ctl`). | Utilizable para pruebas locales cuando exista un driver de Python. |
| Docker | Docker 29.4.3; el daemon puede iniciarse, pero Docker Hub y ECR Public responden 403. | Las imágenes no pueden construirse aquí con la imagen base oficial; se validaron con una base sustituta (ver ADR-0011). |

## 2. Caso de uso inicial (supuesto configurable)

**Certificado de finalización de curso.** Un emisor (universidad, centro de formación o empresa) certifica que un titular completó un curso.

Atributos de la plantilla por defecto (configurables por plantilla):

| Atributo | Divulgación selectiva | Justificación |
|---|---|---|
| `course.title` | No | Es el objeto del certificado. |
| `course.hours` | No | Dato no personal. |
| `completion_date` | Sí | Puede revelar información temporal del titular. |
| `given_name`, `family_name` | Sí | Dato personal; el titular decide cuándo mostrarlo. |
| `grade` | Sí | Dato potencialmente sensible. |
| `student_id` | Sí (opcional) | Identificador del emisor; correlacionable. |

## 3. Supuestos (reversibles, documentados)

| # | Supuesto | Cómo se revierte |
|---|---|---|
| S1 | Un solo perfil de credencial en el MVP: **SD-JWT VC + ES256 + Token Status List** (ver `01-perfil-interoperabilidad.md`). | Abstracción `CredentialFormat`; un segundo formato es un módulo adicional. |
| S2 | La entrega al titular usa **OID4VCI 1.0, flujo pre-autorizado con `tx_code`**. El titular necesita un wallet compatible o la herramienta de demostración. | Se puede añadir flujo de código de autorización. |
| S3 | La presentación en el MVP usa una **API propia** (`/v1/presentation-requests` + `/v1/verifications`) con KB-JWT; **OID4VP queda pendiente**. | Módulo `verification` independiente del transporte. |
| S4 | Identificación del emisor por **JWT VC Issuer Metadata** (`/.well-known/jwt-vc-issuer/...`) alojada por Aletheia en nombre de cada organización. Sin DID ni X.509 en el MVP. | Añadir `x5c` para conformidad HAIP. |
| S5 | Aletheia **no conserva el contenido completo** de las credenciales ni los atributos personales tras la entrega. Los atributos se retienen cifrados solo mientras la oferta está pendiente (máx. 7 días). | Configurable por organización a un valor menor. |
| S6 | Un dominio público por despliegue (p. ej. `aletheia.example`); cada emisor es una ruta, no un subdominio. | Dominios propios de emisor en fase posterior. |
| S7 | Región AWS de referencia: `us-east-1` para estimación de costos (la más económica y con todos los servicios). Para clientes en Uruguay podría preferirse `sa-east-1`; decisión comercial/legal pendiente. | Variable de Terraform. |
| S8 | Idioma del panel: español. API y códigos de error: inglés (convención de integraciones). | — |

## 4. Objetivos no funcionales iniciales (supuestos medibles, **no verificados**)

| Métrica | Objetivo MVP | Cómo se medirá |
|---|---|---|
| Latencia p95 `POST /v1/credentials` (crear oferta) | < 300 ms | Prueba de carga k6/locust en staging |
| Latencia p95 endpoint de credencial OID4VCI (firma KMS incluida) | < 600 ms | Ídem |
| Latencia p95 `POST /v1/verifications` (emisor alojado) | < 300 ms | Ídem |
| Disponibilidad mensual API | 99,5 % (una región, Multi-AZ) | Alarmas CloudWatch sobre ALB 5xx y health checks |
| Propagación de revocación | Inmediata para verificaciones en Aletheia; ≤ `ttl` (300 s) para verificadores externos con caché | Prueba automatizada (criterio 5) |
| RPO / RTO | 5 min / 4 h | PITR de RDS + ensayo de restauración documentado |

## 5. Restricción bloqueante del entorno

> **Actualización (incremento 2, 2026-09-30):** la restricción quedó levantada. Con acceso a PyPI,
> Docker Hub y GHCR se generó `uv.lock`, se construyeron las imágenes oficiales y se ejecutó la
> pila completa. Se conserva el texto original como registro. Sigue pendiente la prueba de
> interoperabilidad con `@sd-jwt/sd-jwt-vc` (npm) y `terraform init` con proveedores sí funciona.

El stack obligatorio (FastAPI, SQLAlchemy, Alembic, psycopg, boto3) no está instalado y los registros de paquetes están bloqueados. Consecuencias:

- **Incremento 1** se completó íntegramente: el núcleo criptográfico sólo depende de `cryptography` y `PyJWT`, que sí están disponibles.
- **Incrementos 2–6** requieren acceso a PyPI (y a npm para la prueba de interoperabilidad con `@sd-jwt/sd-jwt-vc`, y a HashiCorp para `terraform validate`). Sin ese acceso, el código de API y persistencia podría escribirse pero **no ejecutarse ni probarse aquí**.

## 6. Fuera de alcance del MVP

Facturación real, apps móviles, wallet propio, marketplace, emisión masiva a gran escala, múltiples formatos, multirregión, suspensión temporal de credenciales, dominios propios por emisor, conformidad HAIP completa.

## 7. Aspectos legales

No se afirma cumplimiento de ninguna normativa (p. ej., Ley 18.331 de Protección de Datos Personales de Uruguay, GDPR, eIDAS 2). El diseño minimiza datos para facilitar ese análisis, que debe hacerse con asesoría legal.
