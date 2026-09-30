# ADR-0006 · Gestión de claves de firma

- Estado: Aceptada · 2026-09-30

## Decisión
- **Producción/staging:** una clave AWS KMS asimétrica `ECC_NIST_P256`, uso `SIGN_VERIFY`, por organización emisora. La aplicación guarda sólo el ARN, el `kid` y la clave pública (JWK). Firma con `kms:Sign`, `SigningAlgorithm=ECDSA_SHA_256`, `MessageType=DIGEST` (hash local, porque `RAW` admite ≤ 4096 bytes) y conversión DER → R||S.
- **Desarrollo:** `LocalDevSigner` con PEM en un directorio excluido del repositorio (`.dev-keys/`). La aplicación **se niega a iniciar** con este firmante si `ALETHEIA_ENV` no es `development` o `test`.
- Las claves privadas nunca se guardan en la base de datos, logs ni repositorio.
- `kid` = huella JWK SHA-256 (RFC 7638) de la clave pública.

## Ciclo de vida
| Estado | Firma nuevas | Publicada en JWKS | Credenciales ya emitidas |
|---|---|---|---|
| `active` | Sí (una por organización) | Sí | Válidas |
| `retired` | No | Sí, hasta `retired_at + max_validez_credenciales` | Siguen válidas |
| `compromised` | No | **No** | Verificación falla (`key_compromised`) → inválidas; el emisor debe reemitir |

Rotación programada: anual o bajo demanda. La clave KMS retirada se deshabilita para firma pero **no se elimina** mientras existan credenciales vigentes (la clave pública se conserva en la base de datos de forma indefinida para auditoría).

## Respuesta ante compromiso
1. Marcar `compromised` (acción del owner con MFA/confirmación, auditada).
2. Crear nueva clave activa.
3. Deshabilitar la clave KMS (`DisableKey`), revisar CloudTrail.
4. Identificar credenciales afectadas (`issuance.signing_key_id`) y notificar al emisor para reemisión.
