-- Pruebas con el rol de la aplicación: puede operar sobre el negocio pero no
-- alterar la auditoría ni el esquema.
\set ON_ERROR_STOP on
BEGIN;

-- Row-Level Security (0004): sin organización fijada, el rol de la aplicación no ve filas.
DO $$
BEGIN
  IF (SELECT count(*) FROM organization) <> 0 OR (SELECT count(*) FROM audit_event) <> 0 THEN
    RAISE EXCEPTION 'RLS: el rol de la app ve filas sin app.current_org';
  END IF;
END $$;
-- La app tampoco puede reescribir la revisión del esquema.
DO $$
BEGIN
  UPDATE alembic_version SET version_num = version_num;
  RAISE EXCEPTION 'la app pudo modificar alembic_version';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
-- El resto de estas pruebas crea datos propios: organización fijada.
SELECT set_config('app.current_org', '00000000-0000-7000-8000-0000000000f1', true);

INSERT INTO organization (id, public_id, name)
  VALUES ('00000000-0000-7000-8000-0000000000f1', 'org_zzzzzzzzzzzzzzzzzzzzzz', 'Org de la app');
INSERT INTO audit_event (id, organization_id, actor_type, action)
  VALUES ('00000000-0000-7000-8000-0000000000f2', '00000000-0000-7000-8000-0000000000f1', 'system', 'organization.created');
SELECT count(*) AS audit_rows FROM audit_event WHERE id = '00000000-0000-7000-8000-0000000000f2' \gset
\if :audit_rows
\else
  \echo 'la app no puede leer audit_event'
  \quit 1
\endif

DO $$
BEGIN
  UPDATE audit_event SET action = 'x.y' WHERE id = '00000000-0000-7000-8000-0000000000f2';
  RAISE EXCEPTION 'la app pudo modificar audit_event';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
DO $$
BEGIN
  DELETE FROM audit_event WHERE id = '00000000-0000-7000-8000-0000000000f2';
  RAISE EXCEPTION 'la app pudo borrar audit_event';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
DO $$
BEGIN
  CREATE TABLE intrusa (id int);
  RAISE EXCEPTION 'la app pudo crear tablas';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
DO $$
BEGIN
  ALTER TABLE organization ADD COLUMN extra text;
  RAISE EXCEPTION 'la app pudo alterar el esquema';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;

ROLLBACK;
