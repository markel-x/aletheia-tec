-- Reversión del esquema inicial. Sólo para entornos de desarrollo y pruebas:
-- destruye todos los datos.
DROP TABLE IF EXISTS
  rate_limit_bucket, oid4vci_access_token, oid4vci_nonce, idempotency_record,
  usage_event, audit_event, verification_record, presentation_request,
  trusted_issuer, trust_policy, issuance_pending_claims, issuance,
  credential_status, status_list, template_version, credential_template,
  signing_key, issuer_profile, api_client, session, membership,
  user_account, organization
CASCADE;

DROP FUNCTION IF EXISTS audit_event_guard();
DROP FUNCTION IF EXISTS template_version_guard();
DROP FUNCTION IF EXISTS set_updated_at();

DROP TYPE IF EXISTS usage_kind, actor_type, verification_result, status_list_state,
  revocation_reason, issuance_state, template_state, key_state, key_backend,
  membership_role, user_status, organization_status;
