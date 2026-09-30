# ADR-0002 · Perfil de credencial: SD-JWT VC + ES256 + Token Status List

- Estado: Aceptada · 2026-09-30
- Detalle completo: `docs/01-perfil-interoperabilidad.md`

## Decisión
Perfil único `ALT-P1`: SD-JWT VC (draft-19, sobre RFC 9901), `typ: dc+sd-jwt`, ES256, vinculación `cnf.jwk` + KB-JWT, Token Status List (draft-21) con 1 bit.

## Motivos
- Divulgación selectiva sin canonicalización JSON-LD.
- ES256 es el mínimo común de HAIP 1.0 y está soportado por AWS KMS (`ECC_NIST_P256`).
- Ecosistema OID4VC activo, bibliotecas independientes para pruebas (OWF `@sd-jwt/*`).

## Riesgos
- Especificaciones SD-JWT VC y Token Status List aún no publicadas como RFC. Mitigación: versión fijada, pruebas con vectores, revisión al publicarse.
- No es conforme con HAIP (ver brechas en el perfil).
- Sector educativo puede requerir Open Badges 3.0 → posible segundo formato.
