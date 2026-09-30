# ADR-0015 · OID4VP con solicitudes firmadas (x509) y respuestas cifradas

- Estado: Aceptada · 2026-09-30 · Amplía ADR-0014

## Contexto
ADR-0014 dejó sólo el prefijo `redirect_uri:` (solicitud sin firmar) y respuestas en claro. Los wallets
alineados con HAIP y el ecosistema EUDI exigen saber **quién pide** los datos (solicitud firmada con un
certificado) y protegen la respuesta cifrándola al verificador.

## Decisión
- **Identificadores de cliente** `x509_hash:` (por defecto; HAIP) y `x509_san_dns:`. La solicitud es un
  JWT `typ: oauth-authz-req+jwt`, `alg: ES256`, con `x5c` (cadena, hoja primero), `aud`
  `https://self-issued.me/v2` y `exp` = vencimiento de la solicitud. Se sirve **por referencia**:
  el enlace `openid4vp://` sólo lleva `client_id` y `request_uri`.
  - `x509_hash`: `client_id = x509_hash:` + base64url(SHA-256(DER de la hoja)).
  - `x509_san_dns`: el host público debe ser un nombre DNS presente en el SAN de la hoja; si no, 422.
- **Respuesta cifrada** `direct_post.jwt` (por defecto): clave efímera P-256 por sesión, publicada en
  `client_metadata.jwks` (`use: enc`, `alg: ECDH-ES`, `kid` aleatorio) con
  `encrypted_response_enc_values_supported: [A128GCM, A256GCM]`. El wallet envía `response=<JWE>`;
  Aletheia localiza la sesión por `kid`, descifra y exige que el `state` interno sea el de esa sesión.
  - JWE implementado sobre `cryptography` (`platform/jwe.py`): sólo `ECDH-ES` directo + AES-GCM, sin `zip`
    ni `crit`, `epk` validada en la curva; comprobado con el vector de RFC 7518 Apéndice C y contra
    `jose` (implementación independiente).
  - **Sin rebaja**: una sesión creada con cifrado rechaza respuestas en claro, y viceversa.
- **Identidad del verificador** de la **plataforma** (no por organización): clave P-256 y cadena PEM desde
  Secrets Manager (`ALETHEIA_VERIFIER_KEY_PEM`, `ALETHEIA_VERIFIER_CERT_CHAIN_PEM`; en Terraform
  `verifier_identity_secret_arn`). Sin ellas en un entorno desplegado sólo queda `redirect_uri:`. En
  desarrollo se genera un certificado **autofirmado** para el host público.
- **Material de un uso**: la clave privada de respuesta se guarda cifrada (envelope) y, junto con la
  solicitud firmada (que contiene `nonce` y `state`), se borra al completar la sesión o a los 15 minutos.

## Alternativas y límites
- Clave del verificador en **KMS** en vez de un secreto: firmar solicitudes con KMS es directo
  (`KmsSigner`), pero obtener el certificado exige una CSR firmada con la clave de KMS, que
  `cryptography` no genera sin la clave privada. Se deja como mejora; el riesgo de una clave de
  verificador en Secrets Manager es menor que el de una de emisor (permite suplantar solicitudes, no
  emitir credenciales).
- **Certificado por organización**: los wallets mostrarían la organización y no Aletheia; requiere
  emitir certificados a cada cliente (una CA o un proveedor). Pendiente de requisito comercial.
- **Confianza**: un wallet real sólo aceptará el certificado si su emisor está en su lista de confianza
  (en EUDI, certificados de acceso registrados). Eso no es un problema técnico de Aletheia sino de alta
  como verificador en cada ecosistema.
