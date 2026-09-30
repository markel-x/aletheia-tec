# ADR-0004 · Identificación del emisor mediante JWT VC Issuer Metadata

- Estado: Aceptada · 2026-09-30

## Decisión
- `iss` = `https://{host}/issuers/{org_public_id}` (identificador público opaco, no el nombre de la organización, para permitir renombrar sin romper credenciales).
- Metadatos en `https://{host}/.well-known/jwt-vc-issuer/issuers/{org_public_id}` con `issuer` y `jwks` inline.
- Cabecera `kid` obligatoria.

## Alternativas
- `x5c` + PKI (exigido por HAIP): requiere una CA y política de certificados; postergado.
- `did:web`: equivalente en función, menor soporte en el ecosistema SD-JWT VC.
- Dominios propios de cada emisor: mejor señal de confianza para el verificador, pero requiere delegación DNS/TLS; postergado.

## Consecuencias
- La **confianza** en el emisor no se deriva de poder resolver la clave: el verificador necesita una política que liste `iss` aceptados. Resolver ≠ confiar.
- Aletheia es un punto de publicación común: su disponibilidad afecta la verificación online.
