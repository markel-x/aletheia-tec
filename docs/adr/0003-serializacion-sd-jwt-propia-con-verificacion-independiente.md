# ADR-0003 · Serialización SD-JWT propia; firma por `Signer`, verificación JWS con PyJWT

- Estado: Aceptada · 2026-09-30

## Contexto
La biblioteca Python de referencia (`sd-jwt`, OWF) necesita objetos de clave privada locales. Las claves de producción viven en AWS KMS y no pueden extraerse.

## Decisión
- La construcción de disclosures, digests, `_sd`, selección de disclosures y `sd_hash` se implementa en `aletheia.vc.sdjwt` siguiendo RFC 9901 §4–5.
- La firma se abstrae en un protocolo `Signer` (`sign(signing_input) -> raw R||S`). Implementaciones: `LocalDevSigner` (sólo desarrollo) y `KmsSigner`.
- **Toda verificación de firma** usa PyJWT + `cryptography`, una implementación JWS distinta de la que produce las firmas.
- No se implementa ningún primitivo criptográfico: SHA-256 (`hashlib`), ECDSA (`cryptography`/KMS), CSPRNG (`secrets`).

## Evidencia requerida
1. Vectores de RFC 9901 (disclosure y digest de ejemplo).
2. Verificación cruzada con PyJWT.
3. CI: verificación de credenciales Aletheia con `@sd-jwt/sd-jwt-vc` (independiente, TypeScript).

## Consecuencias
Mantenemos ≈200 líneas de serialización. Si OWF añade firmantes remotos, reevaluar.
