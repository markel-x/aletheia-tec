# Runbook de operación

Entorno AWS descrito en `infra/terraform`. Los nombres usan `aletheia-<entorno>`.
Logs: CloudWatch `/aletheia/<entorno>/app` (JSON; buscar por `request_id`).

## Despliegue

1. `main` → CI → `deploy.yml` (staging automático; production con aprobación del entorno de GitHub).
2. El pipeline publica la imagen (etiqueta = commit, inmutable), exige escaneo ECR sin CRITICAL,
   registra revisiones de tarea, ejecuta `migrate` como tarea única y actualiza el servicio `api`.
3. El circuit breaker de ECS revierte solo si las tareas nuevas no superan `/readyz`.

**Migraciones compatibles hacia atrás.** Durante el despliegue conviven la versión anterior y la nueva
contra el esquema nuevo: añadir antes de usar; eliminar en un despliegue posterior. `/readyz` devuelve
`schema_out_of_date` si la revisión de la base no es la que espera el código.

### Revertir la aplicación
```bash
aws ecs update-service --cluster aletheia-<entorno> --service api --task-definition <familia>:<revisión anterior>
aws ecs wait services-stable --cluster aletheia-<entorno> --services api
```
Las migraciones no se revierten automáticamente. Si hace falta, `migrate` con
`python -m aletheia` desde una tarea única y `alembic downgrade` al destino, **sólo** tras evaluar la
pérdida de datos (p. ej. `0005` → `0004` deja ofertas HMAC sin canjear: reemitir).

## Alarmas

### api-5xx
1. Logs: `{ $.level = "ERROR" }` en la última hora; agrupar por `exc_class`.
2. ¿Coincide con un despliegue? → revertir (arriba).
3. `DependencyUnavailable` / KMS → revisar límites de KMS y el estado de AWS en la región.

### readyz
`/readyz` falla con motivo en el cuerpo:
- `database_unavailable`: estado de RDS, conexiones (`DatabaseConnections`), grupo de seguridad.
- `schema_out_of_date`: la tarea `migrate` no corrió o falló; revisar sus logs y relanzarla.

### latency-p95 / api-cpu-saturated
La prueba de carga muestra saturación por CPU (≈ 65 ofertas/s por réplica). Confirmar que el
autoescalado actuó (`DesiredCount`); si está en el máximo, subir `api_max_count` y `apply`.

### maintenance
La purga no registró `maintenance finished` en una hora. Revisar EventBridge Scheduler
(`aletheia-<entorno>-maintenance`) y los logs de la última tarea `maintenance`. Mientras no corra, los
claims pendientes de ofertas vencidas no se borran (ADR-0009): prioridad alta.

## Clave de firma comprometida (ADR-0006)
1. Propietario de la organización: panel → Claves de firma → "Declarar comprometida" (o
   `POST /v1/signing-keys/{id}/compromise`). Sale del JWKS, se deshabilita en KMS y se crea otra.
2. CloudTrail: `kms:Sign` sobre la clave en el periodo sospechoso.
3. Credenciales afectadas: `issuance.signing_key_id = <id>` → avisar al emisor para reemitir.

## Rotación de secretos
- **Contraseña del propietario de RDS**: la rota RDS (Secrets Manager); `migrate` la lee al arrancar.
- **Contraseña de `aletheia_app`**: nueva versión del secreto `…/app-db-password`, ejecutar `migrate`
  (la aplica con `ALTER ROLE`) y forzar un despliegue del servicio para que las tareas la lean.
- **`tx_code` (ADR-0013)**: rotar invalida los `tx_code` de ofertas pendientes; avisar a los emisores
  o regenerar con `offer:reset` tras la rotación.

## Restauración de la base (RPO 5 min / RTO 4 h)
1. `aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier aletheia-<entorno>
   --target-db-instance-identifier aletheia-<entorno>-restore --restore-time <UTC>`.
2. Verificar datos en la instancia restaurada; `terraform state` / `import` para sustituir la instancia o
   cambiar el host en la variable del DSN y desplegar.
3. **Pendiente**: ensayo documentado de restauración con tiempos reales (no realizado todavía).

## Alta de una organización
Tarea única con el comando `bootstrap` y `ALETHEIA_BOOTSTRAP_PASSWORD` desde un secreto temporal:
```bash
aws ecs run-task ... --overrides '{"containerOverrides":[{"name":"migrate","command":["bootstrap","--name","…","--owner-email","…","--owner-name","…"]}]}'
```
La contraseña se entrega al propietario por un canal seguro y se borra el secreto temporal.

## «Pruébelo ahora» (credencial de muestra en la página de inicio)
1. Crear la organización de demostración con `bootstrap` (por ejemplo «CredoSeal Demo»).
2. Crear y publicar su plantilla: tarea única con `["demo-setup","--organization","org_…"]`
   (idempotente; crea la plantilla `demo` con `given_name` y `member_id`).
3. `demo_organization = "org_…"` en el `.tfvars` del entorno y `terraform apply`. Sin esa variable,
   la sección queda oculta y `/public/demo-credential` responde 404.

Límites: 5 por red (/24, /64) por hora y `ALETHEIA_DEMO_DAILY_LIMIT` (300) por día en total.
