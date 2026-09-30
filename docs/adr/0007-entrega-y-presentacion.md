# ADR-0007 · Entrega con OID4VCI pre-autorizado; presentación con API propia

- Estado: Aceptada · 2026-09-30

## Entrega (OID4VCI 1.0)
- `POST /v1/credentials` crea una **oferta**; no firma nada todavía (la clave del titular se conoce recién en el proof).
- La oferta se entrega por referencia: `openid-credential-offer://?credential_offer_uri=https://{host}/oid4vci/offers/{offer_id}`; `offer_id` es aleatorio (≥128 bits) y la URL no contiene datos personales.
- `tx_code` numérico de 6 dígitos, devuelto **una sola vez** al emisor para que lo comunique al titular por un canal distinto. Máx. 5 intentos; luego la oferta se bloquea.
- `pre-authorized_code` de un solo uso, expira con la oferta (default 72 h, máx. 7 días).
- Token de acceso opaco, 5 min, un solo uso para el Credential Endpoint.
- Proof `jwt` (`typ: openid4vci-proof+jwt`, ES256, `aud`, `iat`, `nonce` del Nonce Endpoint, nonce de un solo uso).
- Al firmar: la credencial se devuelve al wallet y **se descartan** los atributos personales almacenados para la oferta. Estado `issued` (= recepción confirmada por el protocolo).

No incluido: flujo de código de autorización, DPoP, wallet/key attestation, emisión diferida, cifrado de respuesta.

## Presentación (MVP)
- `POST /v1/presentation-requests` (verificador autenticado) → `{nonce, aud, expires_at}`.
- `POST /v1/verifications` con `{presentation, presentation_request_id}` → verifica y consume el nonce (anti-replay). El consumo es atómico (`UPDATE … WHERE consumed_at IS NULL RETURNING`) y ocurre **sólo después** de validar firma, KB-JWT y `sd_hash`, para que una presentación inválida no invalide la solicitud.
- Una presentación con KB-JWT pero sin solicitud asociada resulta `indeterminate` (`request_context_missing`): sin `aud`/`nonce` esperados no se puede descartar un replay (RFC 9901 §7.3).
- `POST /v1/verifications` sin `presentation_request_id` permite verificar una credencial sin KB-JWT; el resultado lo indica y la política decide si es aceptable.

OID4VP 1.0 (DCQL, `direct_post`, respuestas cifradas) queda pendiente. Hasta entonces **no existe presentación desde wallets estándar** hacia Aletheia.
