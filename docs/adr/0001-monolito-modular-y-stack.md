# ADR-0001 · Monolito modular en Python sobre AWS

- Estado: Aceptada · 2026-09-30
- Contexto: El stack está fijado (Python, FastAPI, Pydantic, PostgreSQL/SQLAlchemy/Alembic, Terraform, AWS). Equipo pequeño, MVP, requisitos fuertes de aislamiento por organización y de seguridad de claves.

## Decisión
Un único servicio desplegable (`aletheia-api`) organizado en módulos con fronteras explícitas:
`organizations`, `authz`, `issuance`, `verification`, `status`, `audit`, `usage`, más `vc` (núcleo de formato y firma, sin dependencias de web ni de base de datos) y `platform` (configuración, base de datos, logging, errores).

Reglas de dependencia: los módulos sólo se comunican por sus servicios públicos (`service.py`), nunca por tablas de otro módulo; `vc` no importa nada de la aplicación.

Una sola imagen de contenedor ejecuta tres roles mediante comandos: `api`, `migrate` y `maintenance` (tarea programada).

## Alternativas
- Microservicios (emisión / verificación / estado): rechazado; no hay necesidad operativa de escalar por separado y multiplica superficie de IAM, red y despliegue.
- Separar el firmante en un servicio aislado: **reconsiderar** si se incorporan claves HSM dedicadas o requisitos de certificación; con KMS el aislamiento lo da IAM (sólo el rol de la tarea puede `kms:Sign`).

## Consecuencias
- Despliegue y rollback atómicos. Transacciones locales (sin sagas).
- La extracción futura de `verification` o `status` es viable porque no comparten tablas.
