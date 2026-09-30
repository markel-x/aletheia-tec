-- Esquema inicial de Aletheia. Transcripción de docs/03-modelo-de-datos.md.
--
-- Se ejecuta una sola vez al inicializar el volumen de PostgreSQL. En el
-- incremento 2 este archivo se convierte en la primera migración Alembic;
-- hasta entonces es la fuente de verdad ejecutable del modelo.
--
-- Convenciones (doc 03): id UUID generado en la aplicación (v7); public_id con
-- prefijo + 22 caracteres base62; toda tabla de negocio lleva organization_id
-- y sus índices compuestos empiezan por él; timestamptz en UTC.

\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------------
-- Tipos enumerados
-- ---------------------------------------------------------------------------
CREATE TYPE organization_status AS ENUM ('active', 'suspended');
CREATE TYPE user_status         AS ENUM ('active', 'disabled');
CREATE TYPE membership_role     AS ENUM ('owner', 'admin', 'issuer', 'verifier', 'auditor');
CREATE TYPE key_backend         AS ENUM ('local_dev', 'aws_kms');
CREATE TYPE key_state           AS ENUM ('active', 'retired', 'compromised');
CREATE TYPE template_state      AS ENUM ('draft', 'published');
CREATE TYPE issuance_state      AS ENUM ('offered', 'issued', 'offer_expired', 'revoked');
CREATE TYPE revocation_reason   AS ENUM ('superseded', 'issued_in_error', 'holder_request',
                                         'policy_violation', 'key_compromise', 'other');
CREATE TYPE status_list_state   AS ENUM ('open', 'full');
CREATE TYPE verification_result AS ENUM ('valid', 'invalid', 'indeterminate');
CREATE TYPE actor_type          AS ENUM ('user', 'api_client', 'system', 'holder');
CREATE TYPE usage_kind          AS ENUM ('credential.offered', 'credential.issued',
                                         'verification.performed', 'status_list.served');

-- ---------------------------------------------------------------------------
-- Función utilitaria: mantiene updated_at
-- ---------------------------------------------------------------------------
CREATE FUNCTION set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------------------
-- Organizaciones, usuarios, membresías
-- ---------------------------------------------------------------------------
CREATE TABLE organization (
  id                  uuid PRIMARY KEY,
  public_id           text NOT NULL UNIQUE CHECK (public_id ~ '^org_[0-9A-Za-z]{22}$'),
  name                text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  status              organization_status NOT NULL DEFAULT 'active',
  data_retention_days integer NOT NULL DEFAULT 365 CHECK (data_retention_days >= 365),
  deleted_at          timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_account (
  id            uuid PRIMARY KEY,
  email         citext NOT NULL UNIQUE,
  display_name  text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
  password_hash text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
  status        user_status NOT NULL DEFAULT 'active',
  last_login_at timestamptz,
  deleted_at    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE membership (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization (id),
  user_id         uuid NOT NULL REFERENCES user_account (id),
  role            membership_role NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, user_id)
);
CREATE INDEX membership_user_idx ON membership (user_id);

CREATE TABLE session (
  id              uuid PRIMARY KEY,
  user_id         uuid NOT NULL REFERENCES user_account (id),
  organization_id uuid NOT NULL REFERENCES organization (id),
  token_hash      bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  ip_prefix       text CHECK (ip_prefix IS NULL OR ip_prefix ~ '^[0-9a-f.:]+/(24|64)$'),
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX session_expires_idx ON session (expires_at);

CREATE TABLE api_client (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization (id),
  name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  key_prefix      text NOT NULL UNIQUE CHECK (key_prefix ~ '^ak_[0-9A-Za-z]{8}$'),
  secret_hash     bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
  permissions     text[] NOT NULL DEFAULT '{}',
  expires_at      timestamptz,
  revoked_at      timestamptz,
  last_used_at    timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at IS NULL OR expires_at <= created_at + interval '1 year')
);
CREATE INDEX api_client_org_revoked_idx ON api_client (organization_id, revoked_at);

-- ---------------------------------------------------------------------------
-- Emisor y claves
-- ---------------------------------------------------------------------------
CREATE TABLE issuer_profile (
  organization_id                 uuid PRIMARY KEY REFERENCES organization (id),
  display_name                    text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
  issuer_path_id                  text NOT NULL UNIQUE,
  default_credential_validity_days integer NOT NULL DEFAULT 365
                                    CHECK (default_credential_validity_days BETWEEN 1 AND 3650),
  offer_ttl_hours                 integer NOT NULL DEFAULT 72 CHECK (offer_ttl_hours BETWEEN 1 AND 168),
  enabled                         boolean NOT NULL DEFAULT true,
  created_at                      timestamptz NOT NULL DEFAULT now(),
  updated_at                      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE signing_key (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization (id),
  kid             text NOT NULL UNIQUE,
  backend         key_backend NOT NULL,
  key_ref         text NOT NULL,                          -- ARN o nombre de archivo; nunca material privado
  public_jwk      jsonb NOT NULL CHECK (public_jwk ? 'kty' AND NOT public_jwk ? 'd'),
  alg             text NOT NULL DEFAULT 'ES256' CHECK (alg = 'ES256'),
  state           key_state NOT NULL DEFAULT 'active',
  activated_at    timestamptz NOT NULL DEFAULT now(),
  retired_at      timestamptz,
  compromised_at  timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (state <> 'retired'     OR retired_at     IS NOT NULL),
  CHECK (state <> 'compromised' OR compromised_at IS NOT NULL)
);
-- Una única clave activa por organización.
CREATE UNIQUE INDEX signing_key_one_active_idx ON signing_key (organization_id) WHERE state = 'active';

-- ---------------------------------------------------------------------------
-- Plantillas
-- ---------------------------------------------------------------------------
CREATE TABLE credential_template (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization (id),
  public_id       text NOT NULL UNIQUE CHECK (public_id ~ '^tpl_[0-9A-Za-z]{22}$'),
  slug            text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, slug)
);

CREATE TABLE template_version (
  id                    uuid PRIMARY KEY,
  organization_id       uuid NOT NULL REFERENCES organization (id),
  template_id           uuid NOT NULL REFERENCES credential_template (id),
  version               integer NOT NULL CHECK (version >= 1),
  claims_schema         jsonb NOT NULL,
  selective_disclosure  text[] NOT NULL DEFAULT '{}',
  validity_days         integer NOT NULL CHECK (validity_days BETWEEN 1 AND 3650),
  display               jsonb NOT NULL DEFAULT '{}'::jsonb,
  state                 template_state NOT NULL DEFAULT 'draft',
  published_at          timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (template_id, version),
  CHECK (state <> 'published' OR published_at IS NOT NULL)
);

-- Inmutabilidad: una versión publicada no admite cambios de contenido.
CREATE FUNCTION template_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state = 'published' AND (
       NEW.claims_schema IS DISTINCT FROM OLD.claims_schema
    OR NEW.selective_disclosure IS DISTINCT FROM OLD.selective_disclosure
    OR NEW.validity_days IS DISTINCT FROM OLD.validity_days
    OR NEW.display IS DISTINCT FROM OLD.display
    OR NEW.state IS DISTINCT FROM OLD.state
    OR NEW.version IS DISTINCT FROM OLD.version
  ) THEN
    RAISE EXCEPTION 'template_version % is published and immutable', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER template_version_immutable BEFORE UPDATE ON template_version
  FOR EACH ROW EXECUTE FUNCTION template_version_guard();

-- ---------------------------------------------------------------------------
-- Estado (Token Status List)
-- ---------------------------------------------------------------------------
CREATE TABLE status_list (
  id              uuid PRIMARY KEY,
  public_id       text NOT NULL UNIQUE CHECK (public_id ~ '^sl_[0-9A-Za-z]{22}$'),
  organization_id uuid NOT NULL REFERENCES organization (id),
  bits            smallint NOT NULL DEFAULT 1 CHECK (bits IN (1, 2, 4, 8)),
  size            integer NOT NULL DEFAULT 131072 CHECK (size > 0),
  allocated       integer NOT NULL DEFAULT 0 CHECK (allocated >= 0 AND allocated <= size),
  version         bigint NOT NULL DEFAULT 0,
  signing_key_id  uuid NOT NULL REFERENCES signing_key (id),
  state           status_list_state NOT NULL DEFAULT 'open',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX status_list_org_state_idx ON status_list (organization_id, state);

CREATE TABLE credential_status (
  status_list_id  uuid NOT NULL REFERENCES status_list (id),
  idx             integer NOT NULL CHECK (idx >= 0),
  organization_id uuid NOT NULL REFERENCES organization (id),
  value           smallint NOT NULL DEFAULT 0 CHECK (value BETWEEN 0 AND 255),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (status_list_id, idx)
);

-- ---------------------------------------------------------------------------
-- Emisión
-- ---------------------------------------------------------------------------
CREATE TABLE issuance (
  id                     uuid PRIMARY KEY,
  public_id              text NOT NULL UNIQUE CHECK (public_id ~ '^cred_[0-9A-Za-z]{22}$'),
  organization_id        uuid NOT NULL REFERENCES organization (id),
  template_version_id    uuid NOT NULL REFERENCES template_version (id),
  vct                    text NOT NULL,
  state                  issuance_state NOT NULL DEFAULT 'offered',
  holder_reference       text CHECK (holder_reference IS NULL OR char_length(holder_reference) <= 128),
  offer_id               bytea NOT NULL UNIQUE CHECK (octet_length(offer_id) = 16),
  pre_auth_code_hash     bytea NOT NULL CHECK (octet_length(pre_auth_code_hash) = 32),
  tx_code_hash           text NOT NULL CHECK (tx_code_hash LIKE '$argon2id$%'),
  tx_code_attempts       smallint NOT NULL DEFAULT 0 CHECK (tx_code_attempts >= 0),
  offer_expires_at       timestamptz NOT NULL,
  signing_key_id         uuid REFERENCES signing_key (id),
  holder_key_thumbprint  text,
  status_list_id         uuid,
  status_idx             integer,
  issued_at              timestamptz,
  expires_at             timestamptz,
  revoked_at             timestamptz,
  revocation_reason_code revocation_reason,
  revoked_by             uuid,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  UNIQUE (status_list_id, status_idx),
  FOREIGN KEY (status_list_id, status_idx) REFERENCES credential_status (status_list_id, idx),
  -- Coherencia de estado: lo emitido tiene clave, vinculación, índice y fechas;
  -- lo revocado además tiene fecha y motivo.
  CHECK (state NOT IN ('issued', 'revoked') OR (
    signing_key_id IS NOT NULL AND holder_key_thumbprint IS NOT NULL AND
    status_list_id IS NOT NULL AND status_idx IS NOT NULL AND
    issued_at IS NOT NULL AND expires_at IS NOT NULL)),
  CHECK (state <> 'revoked' OR (revoked_at IS NOT NULL AND revocation_reason_code IS NOT NULL))
);
CREATE INDEX issuance_org_created_idx ON issuance (organization_id, created_at DESC);
CREATE INDEX issuance_org_state_idx   ON issuance (organization_id, state);
CREATE INDEX issuance_org_holder_idx  ON issuance (organization_id, holder_reference);

CREATE TABLE issuance_pending_claims (
  issuance_id        uuid PRIMARY KEY REFERENCES issuance (id) ON DELETE CASCADE,
  organization_id    uuid NOT NULL REFERENCES organization (id),
  ciphertext         bytea NOT NULL,
  encrypted_data_key bytea NOT NULL,
  key_ref            text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Verificación
-- ---------------------------------------------------------------------------
CREATE TABLE trust_policy (
  id                     uuid PRIMARY KEY,
  organization_id        uuid NOT NULL REFERENCES organization (id),
  name                   text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  accepted_vcts          text[] NOT NULL DEFAULT '{}',
  required_claims        text[] NOT NULL DEFAULT '{}',
  require_holder_binding boolean NOT NULL DEFAULT true,
  require_status         boolean NOT NULL DEFAULT true,
  max_status_age_seconds integer NOT NULL DEFAULT 900 CHECK (max_status_age_seconds > 0),
  clock_skew_seconds     integer NOT NULL DEFAULT 60 CHECK (clock_skew_seconds BETWEEN 0 AND 300),
  max_kb_age_seconds     integer NOT NULL DEFAULT 300 CHECK (max_kb_age_seconds > 0),
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name)
);

CREATE TABLE trusted_issuer (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization (id),
  trust_policy_id uuid NOT NULL REFERENCES trust_policy (id) ON DELETE CASCADE,
  issuer          text NOT NULL CHECK (issuer ~ '^https://'),
  hosted_org_id   uuid REFERENCES organization (id),
  note            text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (trust_policy_id, issuer)
);

CREATE TABLE presentation_request (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization (id),
  trust_policy_id uuid NOT NULL REFERENCES trust_policy (id),
  nonce_hash      bytea NOT NULL UNIQUE CHECK (octet_length(nonce_hash) = 32),
  aud             text NOT NULL,
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX presentation_request_expires_idx ON presentation_request (expires_at);

CREATE TABLE verification_record (
  id                      uuid PRIMARY KEY,
  organization_id         uuid NOT NULL REFERENCES organization (id),
  presentation_request_id uuid REFERENCES presentation_request (id) ON DELETE SET NULL,
  result                  verification_result NOT NULL,
  checks                  jsonb NOT NULL,
  issuer                  text,
  vct                     text,
  credential_ref          uuid REFERENCES issuance (id) ON DELETE SET NULL,
  created_at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX verification_record_org_created_idx ON verification_record (organization_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Auditoría (append-only) y consumo
-- ---------------------------------------------------------------------------
CREATE TABLE audit_event (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization (id),
  occurred_at     timestamptz NOT NULL DEFAULT now(),
  actor_type      actor_type NOT NULL,
  actor_id        uuid,
  action          text NOT NULL CHECK (action ~ '^[a-z_]+\.[a-z_]+$'),
  target_type     text,
  target_id       uuid,
  request_id      text,
  metadata        jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_event_org_occurred_idx ON audit_event (organization_id, occurred_at DESC);
CREATE INDEX audit_event_org_target_idx   ON audit_event (organization_id, target_id);

-- Refuerzo del carácter append-only más allá de los privilegios del rol.
CREATE FUNCTION audit_event_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_event is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_event_append_only BEFORE UPDATE OR DELETE ON audit_event
  FOR EACH ROW EXECUTE FUNCTION audit_event_guard();

CREATE TABLE usage_event (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization (id),
  occurred_at     timestamptz NOT NULL DEFAULT now(),
  kind            usage_kind NOT NULL,
  api_client_id   uuid REFERENCES api_client (id) ON DELETE SET NULL,
  quantity        integer NOT NULL DEFAULT 1 CHECK (quantity > 0)
);
CREATE INDEX usage_event_org_kind_occurred_idx ON usage_event (organization_id, kind, occurred_at);

-- ---------------------------------------------------------------------------
-- Plataforma: idempotencia, OID4VCI, rate limit
-- ---------------------------------------------------------------------------
CREATE TABLE idempotency_record (
  organization_id uuid NOT NULL REFERENCES organization (id),
  key             text NOT NULL CHECK (char_length(key) BETWEEN 1 AND 255),
  request_hash    bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  response_status smallint NOT NULL CHECK (response_status BETWEEN 100 AND 599),
  response_body   jsonb,
  resource_id     uuid,
  expires_at      timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, key)
);
CREATE INDEX idempotency_record_expires_idx ON idempotency_record (expires_at);

CREATE TABLE oid4vci_nonce (
  nonce_hash  bytea PRIMARY KEY CHECK (octet_length(nonce_hash) = 32),
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX oid4vci_nonce_expires_idx ON oid4vci_nonce (expires_at);

CREATE TABLE oid4vci_access_token (
  token_hash  bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  issuance_id uuid NOT NULL REFERENCES issuance (id) ON DELETE CASCADE,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX oid4vci_access_token_expires_idx ON oid4vci_access_token (expires_at);

CREATE TABLE rate_limit_bucket (
  subject      text NOT NULL,
  window_start timestamptz NOT NULL,
  count        integer NOT NULL DEFAULT 0 CHECK (count >= 0),
  PRIMARY KEY (subject, window_start)
);

-- ---------------------------------------------------------------------------
-- updated_at automático en las tablas que lo tienen
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  FOR t IN
    SELECT table_name FROM information_schema.columns
     WHERE table_schema = 'public' AND column_name = 'updated_at'
       AND table_name <> 'credential_status'
  LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION set_updated_at()',
                   t || '_set_updated_at', t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Privilegios del rol de la aplicación
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO aletheia_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aletheia_app;
REVOKE UPDATE, DELETE ON audit_event FROM aletheia_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_event FROM PUBLIC;
