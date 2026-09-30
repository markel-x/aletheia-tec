# 01 · Perfil de interoperabilidad del MVP: `ALT-P1`

Estado: propuesto e implementado parcialmente (núcleo) · Fecha de consulta de fuentes: 2026-09-30

Un solo perfil para el MVP. Todo lo que no figura aquí **no** está soportado.

## 1. Resumen

| Aspecto | Decisión `ALT-P1` |
|---|---|
| Formato | **SD-JWT VC** — `draft-ietf-oauth-sd-jwt-vc-19` (31-ago-2026, enviado al IESG), sobre **SD-JWT RFC 9901** (nov-2025) |
| Serialización | Compacta: `<JWT emisor>~<Disclosure 1>~…~<Disclosure N>~[<KB-JWT>]` |
| Cabecera JWS | `typ: "dc+sd-jwt"`, `alg: "ES256"`, `kid` obligatorio |
| Algoritmos permitidos | Firma de emisor: **ES256** (ECDSA P-256 + SHA-256). Holder (KB-JWT y proof OID4VCI): **ES256**. Cualquier otro (incl. `none`, `HS*`, `RS*`) se rechaza. |
| Hash de disclosures | `sha-256` (`_sd_alg`) |
| Identificación del emisor | `iss` = URL HTTPS: `https://{host}/issuers/{org_public_id}` |
| Resolución de claves | JWT VC Issuer Metadata: `https://{host}/.well-known/jwt-vc-issuer/issuers/{org_public_id}` con `jwks` inline; selección por `kid` |
| Vinculación con el titular | `cnf.jwk` (clave pública EC P-256 del titular, obtenida del proof OID4VCI). Presentación con **KB-JWT** (`typ: kb+jwt`, `aud`, `nonce`, `iat`, `sd_hash`). |
| Estado / revocación | **Token Status List** — `draft-ietf-oauth-status-list-21` (21-jun-2026, enviado al IESG); `bits: 1` (0 = VALID, 1 = INVALID); JWT `typ: statuslist+jwt`, `ttl: 300` |
| Emisión (entrega) | **OID4VCI 1.0 Final** (sep-2025): oferta por referencia (`credential_offer_uri`), grant pre-autorizado con `tx_code`, Nonce Endpoint, proof `jwt` |
| Presentación | API propia Aletheia con KB-JWT. **OID4VP 1.0 pendiente.** |
| Tipo (`vct`) | URL estable por plantilla: `https://{host}/issuers/{org_public_id}/types/{template_slug}` |

## 2. Detalle por aspecto

### 2.1 Estándar y versión
- **SD-JWT, RFC 9901** — estándar publicado. Madurez alta.
- **SD-JWT VC, draft-19** — borrador en fase de IESG; los cambios esperados son editoriales, pero puede haber rupturas menores (p. ej. el cambio de `vc+sd-jwt` a `dc+sd-jwt` en borradores anteriores). Se fija la versión y se revisa al publicarse el RFC.
- **Token Status List, draft-21** — mismo estado; fijado.
- **OID4VCI 1.0** — especificación final de OpenID Foundation.

### 2.2 Madurez y soporte de bibliotecas

| Biblioteca | Uso en Aletheia | Motivo |
|---|---|---|
| `cryptography` (PyCA) | Claves locales de desarrollo, verificación ECDSA, conversión DER↔raw de firmas | Mantenida, base del ecosistema Python |
| `PyJWT` | Verificación de todos los JWS (JWT de emisor, KB-JWT, proof OID4VCI, status list) | Implementación JWS independiente de nuestro código de firma |
| AWS KMS (`boto3`) | Firma en entornos desplegados | La clave privada nunca sale de KMS |
| `sd-jwt` (OWF, Python, 0.10.x) | **No** se usa en runtime | Requiere objetos de clave privada (`jwcrypto`); no admite firma remota KMS sin modificarla |
| `@sd-jwt/sd-jwt-vc` (OWF, TypeScript) | **Prueba de interoperabilidad en CI** (implementación independiente) | Soporta verificación de SD-JWT VC, KB-JWT y status list |

La construcción de disclosures y digests (≈150 líneas, RFC 9901 §4–5) es **serialización, no criptografía**: los primitivos (SHA-256, ECDSA) provienen de `hashlib`/`cryptography`/KMS. Se valida contra los vectores de prueba del RFC y, en CI, contra la biblioteca independiente de OWF. Ver ADR-0003.

### 2.3 Formato exacto de la credencial

Cabecera del JWT del emisor:
```json
{ "alg": "ES256", "typ": "dc+sd-jwt", "kid": "<kid>" }
```
Payload (antes de reemplazar claims por digests):
```json
{
  "iss": "https://aletheia.example/issuers/org_8Hq2…",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1821536000,
  "vct": "https://aletheia.example/issuers/org_8Hq2…/types/course-completion",
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
  "status": { "status_list": { "idx": 48213, "uri": "https://aletheia.example/status-lists/sl_…" } },
  "course": { "title": "Introducción a la Criptografía", "hours": 40 },
  "_sd": ["<digest given_name>", "<digest family_name>", "<digest completion_date>", "<digest grade>", "<digests señuelo>"],
  "_sd_alg": "sha-256"
}
```
Reglas:
- `iss`, `iat`, `nbf`, `exp`, `vct`, `cnf`, `status` **nunca** son selectivamente divulgables (SD-JWT VC §3.2.2).
- No se incluye `sub`: sería un identificador estable y correlacionable sin beneficio para el caso de uso.
- Se añaden **digests señuelo** (decoys) para ocultar el número de claims divulgables.
- `exp` es obligatorio por política de plataforma (default 5 años, configurable por plantilla; puede omitirse sólo si la plantilla lo declara explícitamente).

### 2.4 Algoritmos permitidos
- Firma: `ES256` exclusivamente. Compatible con AWS KMS `ECC_NIST_P256` / `ECDSA_SHA_256`.
- KMS devuelve firmas **DER** (ANSI X9.62); JWS exige `R || S` de 32+32 bytes → conversión con `cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature`.
- KMS limita `MessageType=RAW` a 4096 bytes; la entrada de firma JWS puede superarlo, por lo que se calcula SHA-256 localmente y se usa `MessageType=DIGEST` (uso documentado por AWS para mensajes ya hasheados).

### 2.5 Resolución y rotación de claves
- Metadatos del emisor publicados por Aletheia con `jwks` inline que incluye claves **activas y retiradas**; excluye claves **comprometidas**.
- Rotación: nueva clave `active`, anterior pasa a `retired` (sigue verificando credenciales ya emitidas hasta su `exp` máximo). Compromiso: estado `compromised` → se retira del JWKS; las credenciales firmadas con ella pasan a **inválidas** (ver ADR-0006).
- Para emisores alojados en la misma instancia, el verificador de Aletheia resuelve la clave desde la base de datos (sin red).
- Emisores externos: sólo se resuelven si figuran en la política de confianza del verificador (evita SSRF y descargas arbitrarias).

### 2.6 Estado y revocación
- Cada credencial recibe un índice **aleatorio** dentro de una lista de 131 072 entradas (16 KiB sin comprimir) para reducir la correlación por orden de emisión.
- La revocación es **irreversible** (`bits: 1`; no se usa `SUSPENDED`).
- El Status List Token se genera y firma a demanda desde el estado en base de datos, con caché de `ttl` segundos. `sub` = URI de la lista.

### 2.7 Limitaciones de privacidad
- La firma del emisor, `cnf.jwk` y `status.idx` son idénticos en cada presentación de una misma credencial → **presentaciones correlacionables** entre verificadores coludidos. Mitigación futura: emisión por lotes (batch issuance) con claves de titular distintas.
- La consulta del Status List revela a Aletheia que *alguna* credencial de esa lista está siendo verificada (no cuál). Tamaño de lista grande = mayor anonimato de grupo.
- El emisor conoce el `idx` de cada titular; podría observar consultas si aloja su propio estado (no es el caso en el MVP: lo aloja Aletheia).

## 3. Relación con HAIP 1.0 (Final, dic-2025)

`ALT-P1` **no es conforme con HAIP**. Brechas:

| Requisito HAIP para `dc+sd-jwt` | `ALT-P1` |
|---|---|
| `x5c` con cadena de certificados del emisor | No (usa metadatos `jwt-vc-issuer`) |
| OID4VCI: flujo de código de autorización | No (sólo pre-autorizado) |
| DPoP | No |
| Wallet Attestation y Key Attestation | No |
| OID4VP con DCQL, respuesta cifrada | No (API propia) |
| ES256 | **Sí** |
| Token Status List | **Sí** |

Consecuencia: wallets que exijan HAIP (p. ej. perfiles EUDI) **no** aceptarán credenciales Aletheia sin trabajo adicional. Es el principal ítem de la hoja de ruta de interoperabilidad.

## 4. Alternativas evaluadas

| Alternativa | Por qué no para el MVP |
|---|---|
| W3C VCDM 2.0 + VC-JOSE-COSE / Bitstring Status List | Estándares W3C Recommendation, pero menor adopción en wallets OID4VC; duplicaría esfuerzo con SD-JWT VC. Candidato a segundo formato. |
| VCDM + Data Integrity (JSON-LD, BBS+) | Canonicalización JSON-LD y resolución de contextos remotos (riesgo SSRF); BBS no disponible en KMS. |
| **Open Badges 3.0 (1EdTech)** | Es el estándar sectorial de educación y encaja con el caso de uso. Se descarta sólo para el primer perfil por su ecosistema específico; **se recomienda validar con el equipo comercial** si los clientes objetivo lo exigen (LMS, portfolios). |
| ISO mdoc (18013-5/-7) | CBOR/COSE, orientado a documentos de identidad en dispositivo; excesivo para certificados de curso. |
| DID (`did:web`, `did:jwk`) | `did:web` equivale funcionalmente a los metadatos `jwt-vc-issuer` pero con menos soporte en el ecosistema SD-JWT VC; `did:jwk` no permite rotación. |
| Blockchain / registros distribuidos | Sin necesidad: la confianza la aporta la firma y la publicación HTTPS; añadiría costo, latencia y riesgos de privacidad (datos inmutables). |

## 5. Qué interoperabilidad existe y cuál no

| Flujo | Disponible en MVP | Interoperabilidad externa |
|---|---|---|
| Emisión a wallet OID4VCI (pre-autorizado, sin DPoP/atestaciones) | Sí (incremento 3) | **No comprobada**. Requiere prueba con un wallet real. |
| Verificación de una credencial emitida por Aletheia con biblioteca independiente | Sí | Prueba automatizada con `@sd-jwt/sd-jwt-vc` planificada (requiere npm) |
| Verificación de credenciales de emisores externos `dc+sd-jwt` | Sí, si el emisor está en la política de confianza y publica `jwt-vc-issuer` | No comprobada |
| Presentación desde un wallet vía OID4VP | **No** | — |
| Descarga de archivo / QR | Se ofrece el QR de la **oferta OID4VCI**, no de la credencial | Un QR no constituye por sí mismo integración con wallets |

## 6. Fuentes

- [RFC 9901 — Selective Disclosure for JWTs](https://www.rfc-editor.org/rfc/rfc9901.html)
- [draft-ietf-oauth-sd-jwt-vc (datatracker)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- [draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html)
- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VC High Assurance Interoperability Profile 1.0 — Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [AWS KMS API — Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
- [sd-jwt (Python, OWF) en PyPI](https://pypi.org/project/sd-jwt/)
- [@sd-jwt/sd-jwt-vc (TypeScript, OWF)](https://unpkg.com/@sd-jwt/sd-jwt-vc@0.20.0/README.md)
