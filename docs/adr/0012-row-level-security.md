# ADR-0012 · Row-Level Security por organización

- Estado: Aceptada · 2026-09-30

## Contexto
El aislamiento por organización se aplica en la capa de servicio (toda consulta filtra por
`organization_id` del principal; otra organización → 404). Un filtro olvidado en un endpoint nuevo
expondría datos de otros clientes. doc 02 §4 preveía RLS como defensa en profundidad.

## Decisión
- Migración `0004`: RLS habilitado en las 18 tablas con `organization_id` y en `organization`, con una
  política `tenant_isolation` (lectura y escritura):
  `app.bypass_rls = 'on' OR organization_id = app.current_org`.
- Las variables se fijan con `set_config(..., true)`: viven sólo en la transacción de la petición.
- `api.deps.get_principal` autentica (con acceso acotado entre organizaciones) y fija
  `app.current_org`. **Sin organización fijada el rol de la aplicación no ve filas** (falla cerrado).
- Rutas sin principal (login, OID4VCI, listas de estado, metadatos públicos) usan
  `SystemSessionDep` de forma explícita; tareas de sistema (`bootstrap`, `maintenance`) usan
  `Database.session(bypass_rls=True)`.
- Accesos entre organizaciones dentro de una petición autenticada, sólo a datos públicos (claves y
  listas de estado de otro emisor alojado al verificar), con el context manager `rls_bypass`, que
  vacía los cambios pendientes antes de restaurar.
- El propietario del esquema no está sujeto a RLS (sin `FORCE`): migraciones y operación.
- Además, el rol de la aplicación pierde escritura sobre `alembic_version`.

## Alcance y límites
- **Protege** frente a errores del código autenticado (filtros olvidados, joins mal hechos).
- **No protege** frente a quien ejecute SQL arbitrario con el rol de la aplicación: podría fijar las
  mismas variables. Un segundo rol de base de datos para los flujos de sistema cerraría ese hueco a
  costa de dos pools de conexión; se reconsiderará si aparece un requisito de certificación.

## Consecuencias
- Todas las pruebas de API corren con el rol `aletheia_app` y RLS activo (`ALETHEIA_TEST_APP_DATABASE_URL`);
  `tests/test_rls.py` y `db/tests/privileges.sql` comprueban la política directamente.
- Coste: una comparación por fila con una variable de sesión; no medible en la prueba de carga.
