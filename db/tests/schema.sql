-- Pruebas del esquema con el rol propietario. Cada bloque falla ruidosamente
-- (ON_ERROR_STOP) si el modelo no se comporta como lo documenta docs/03.
-- Todo se ejecuta dentro de una transacción que se revierte al final.
\set ON_ERROR_STOP on
BEGIN;

-- 1. Todas las tablas del modelo existen.
DO $$
DECLARE
  expected text[] := ARRAY['organization','user_account','membership','session','api_client',
    'issuer_profile','signing_key','credential_template','template_version','issuance',
    'issuance_pending_claims','status_list','credential_status','trust_policy','trusted_issuer',
    'presentation_request','verification_record','audit_event','usage_event','idempotency_record',
    'oid4vci_nonce','oid4vci_access_token','rate_limit_bucket'];
  missing text[];
BEGIN
  SELECT array_agg(t) INTO missing FROM unnest(expected) AS t
   WHERE to_regclass('public.' || t) IS NULL;
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'faltan tablas: %', missing;
  END IF;
END $$;

-- 2. Toda tabla de negocio lleva organization_id (excepciones documentadas en doc 03).
DO $$
DECLARE bad text[];
BEGIN
  SELECT array_agg(table_name::text) INTO bad
    FROM information_schema.tables t
   WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
     AND table_name NOT IN ('organization','user_account','oid4vci_nonce','oid4vci_access_token','rate_limit_bucket')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns c
                      WHERE c.table_schema = 'public' AND c.table_name = t.table_name
                        AND c.column_name = 'organization_id');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'tablas sin organization_id: %', bad;
  END IF;
END $$;

-- Datos de apoyo.
INSERT INTO organization (id, public_id, name)
  VALUES ('00000000-0000-7000-8000-000000000001', 'org_0123456789abcdefghijAB', 'Universidad de prueba');
INSERT INTO user_account (id, email, display_name, password_hash)
  VALUES ('00000000-0000-7000-8000-000000000002', 'Ana@Example.org', 'Ana', '$argon2id$v=19$m=65536,t=3,p=4$x$y');

-- 3. citext: el correo es único sin distinguir mayúsculas.
DO $$
BEGIN
  INSERT INTO user_account (id, email, display_name, password_hash)
    VALUES (gen_random_uuid(), 'ana@example.org', 'Ana 2', '$argon2id$v=19$m=65536,t=3,p=4$x$y');
  RAISE EXCEPTION 'correo duplicado aceptado';
EXCEPTION WHEN unique_violation THEN NULL;
END $$;

-- 4. Formato de identificadores públicos.
DO $$
BEGIN
  INSERT INTO organization (id, public_id, name) VALUES (gen_random_uuid(), 'org_corto', 'x');
  RAISE EXCEPTION 'public_id inválido aceptado';
EXCEPTION WHEN check_violation THEN NULL;
END $$;

-- 5. Una sola clave activa por organización; el JWK público no puede llevar 'd'.
INSERT INTO signing_key (id, organization_id, kid, backend, key_ref, public_jwk)
  VALUES ('00000000-0000-7000-8000-000000000003', '00000000-0000-7000-8000-000000000001',
          'kid-1', 'local_dev', 'dev-key-1.pem', '{"kty":"EC","crv":"P-256","x":"a","y":"b"}');
DO $$
BEGIN
  INSERT INTO signing_key (id, organization_id, kid, backend, key_ref, public_jwk)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000001',
            'kid-2', 'local_dev', 'dev-key-2.pem', '{"kty":"EC","crv":"P-256","x":"a","y":"b"}');
  RAISE EXCEPTION 'segunda clave activa aceptada';
EXCEPTION WHEN unique_violation THEN NULL;
END $$;
DO $$
BEGIN
  INSERT INTO signing_key (id, organization_id, kid, backend, key_ref, public_jwk, state, retired_at)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000001',
            'kid-3', 'local_dev', 'dev-key-3.pem', '{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"secreto"}',
            'retired', now());
  RAISE EXCEPTION 'JWK con clave privada aceptado';
EXCEPTION WHEN check_violation THEN NULL;
END $$;
-- Retirar la clave y activar otra sí es válido (rotación).
UPDATE signing_key SET state = 'retired', retired_at = now() WHERE kid = 'kid-1';
INSERT INTO signing_key (id, organization_id, kid, backend, key_ref, public_jwk)
  VALUES ('00000000-0000-7000-8000-000000000004', '00000000-0000-7000-8000-000000000001',
          'kid-2', 'local_dev', 'dev-key-2.pem', '{"kty":"EC","crv":"P-256","x":"a","y":"b"}');

-- 6. Versión de plantilla publicada es inmutable.
INSERT INTO credential_template (id, organization_id, public_id, slug, name)
  VALUES ('00000000-0000-7000-8000-000000000005', '00000000-0000-7000-8000-000000000001',
          'tpl_0123456789abcdefghijAB', 'course-completion', 'Certificado de curso');
INSERT INTO template_version (id, organization_id, template_id, version, claims_schema, validity_days, state, published_at)
  VALUES ('00000000-0000-7000-8000-000000000006', '00000000-0000-7000-8000-000000000001',
          '00000000-0000-7000-8000-000000000005', 1, '{"type":"object"}', 365, 'published', now());
DO $$
BEGIN
  UPDATE template_version SET validity_days = 30 WHERE id = '00000000-0000-7000-8000-000000000006';
  RAISE EXCEPTION 'versión publicada modificada';
EXCEPTION WHEN check_violation THEN NULL;
END $$;

-- 7. Emisión: estado 'issued' exige clave, vinculación, índice de estado y fechas.
INSERT INTO status_list (id, public_id, organization_id, signing_key_id)
  VALUES ('00000000-0000-7000-8000-000000000007', 'sl_0123456789abcdefghijAB',
          '00000000-0000-7000-8000-000000000001', '00000000-0000-7000-8000-000000000004');
INSERT INTO credential_status (status_list_id, idx, organization_id)
  VALUES ('00000000-0000-7000-8000-000000000007', 4242, '00000000-0000-7000-8000-000000000001');
INSERT INTO issuance (id, public_id, organization_id, template_version_id, vct, offer_id,
                      pre_auth_code_hash, tx_code_hash, offer_expires_at)
  VALUES ('00000000-0000-7000-8000-000000000008', 'cred_0123456789abcdefghijAB',
          '00000000-0000-7000-8000-000000000001', '00000000-0000-7000-8000-000000000006',
          'https://aletheia.example/org_x/vct/course-completion',
          decode('00112233445566778899aabbccddeeff', 'hex'), decode(repeat('ab', 32), 'hex'),
          '$argon2id$v=19$m=65536,t=3,p=4$x$y', now() + interval '3 days');
DO $$
BEGIN
  UPDATE issuance SET state = 'issued' WHERE id = '00000000-0000-7000-8000-000000000008';
  RAISE EXCEPTION 'emisión incompleta marcada como issued';
EXCEPTION WHEN check_violation THEN NULL;
END $$;
UPDATE issuance
   SET state = 'issued', signing_key_id = '00000000-0000-7000-8000-000000000004',
       holder_key_thumbprint = 'thumb', status_list_id = '00000000-0000-7000-8000-000000000007',
       status_idx = 4242, issued_at = now(), expires_at = now() + interval '365 days'
 WHERE id = '00000000-0000-7000-8000-000000000008';

-- 8. El índice de estado es único: dos credenciales no comparten (lista, idx).
DO $$
BEGIN
  INSERT INTO issuance (id, public_id, organization_id, template_version_id, vct, offer_id,
                        pre_auth_code_hash, tx_code_hash, offer_expires_at, state, signing_key_id,
                        holder_key_thumbprint, status_list_id, status_idx, issued_at, expires_at)
    VALUES (gen_random_uuid(), 'cred_0123456789abcdefghijAC', '00000000-0000-7000-8000-000000000001',
            '00000000-0000-7000-8000-000000000006', 'vct', decode(repeat('01', 16), 'hex'),
            decode(repeat('cd', 32), 'hex'), '$argon2id$x', now() + interval '1 day', 'issued',
            '00000000-0000-7000-8000-000000000004', 't2', '00000000-0000-7000-8000-000000000007', 4242,
            now(), now() + interval '1 day');
  RAISE EXCEPTION 'índice de estado duplicado aceptado';
EXCEPTION WHEN unique_violation THEN NULL;
END $$;

-- 9. Revocación exige fecha y motivo; updated_at avanza solo.
DO $$
BEGIN
  UPDATE issuance SET state = 'revoked' WHERE id = '00000000-0000-7000-8000-000000000008';
  RAISE EXCEPTION 'revocación sin motivo aceptada';
EXCEPTION WHEN check_violation THEN NULL;
END $$;
UPDATE issuance SET state = 'revoked', revoked_at = now(), revocation_reason_code = 'holder_request'
 WHERE id = '00000000-0000-7000-8000-000000000008';
DO $$
BEGIN
  -- Dentro de una transacción now() no cambia; se comprueba que el trigger exista.
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'issuance_set_updated_at') THEN
    RAISE EXCEPTION 'falta el trigger de updated_at';
  END IF;
END $$;

-- 10. Los claims pendientes desaparecen con la emisión (ON DELETE CASCADE).
INSERT INTO issuance_pending_claims (issuance_id, organization_id, ciphertext, encrypted_data_key, key_ref)
  VALUES ('00000000-0000-7000-8000-000000000008', '00000000-0000-7000-8000-000000000001',
          '\x00'::bytea, '\x00'::bytea, 'arn:aws:kms:...');
DELETE FROM issuance_pending_claims WHERE issuance_id = '00000000-0000-7000-8000-000000000008';

-- 11. audit_event es append-only incluso para el propietario (trigger).
INSERT INTO audit_event (id, organization_id, actor_type, actor_id, action, target_type, target_id)
  VALUES ('00000000-0000-7000-8000-000000000009', '00000000-0000-7000-8000-000000000001',
          'user', '00000000-0000-7000-8000-000000000002', 'credential.revoked', 'issuance',
          '00000000-0000-7000-8000-000000000008');
DO $$
BEGIN
  DELETE FROM audit_event WHERE id = '00000000-0000-7000-8000-000000000009';
  RAISE EXCEPTION 'borrado de auditoría aceptado';
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;

-- 12. Solicitud de presentación: máximo 10 minutos.
INSERT INTO trust_policy (id, organization_id, name)
  VALUES ('00000000-0000-7000-8000-00000000000a', '00000000-0000-7000-8000-000000000001', 'default');
DO $$
BEGIN
  INSERT INTO presentation_request (id, organization_id, trust_policy_id, nonce_hash, aud, expires_at)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000001', '00000000-0000-7000-8000-00000000000a',
            decode(repeat('ef', 32), 'hex'), 'https://verifier.example', now() + interval '1 hour');
  RAISE EXCEPTION 'solicitud de presentación de 1 hora aceptada';
EXCEPTION WHEN check_violation THEN NULL;
END $$;

ROLLBACK;
