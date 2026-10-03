# ADR-0018 · Custodia de claves del emisor: gestionada por CredoSeal o externa (BYOK)

- Estado: **Propuesta** · 2026-10-03 (sin implementar; la página de inicio la ofrece «a pedido»)

## Contexto
Hoy cada organización tiene una clave de firma ECDSA P-256 por organización en AWS KMS, creada y
custodiada por CredoSeal (ADR-0006). Instituciones reguladas (gobiernos, banca, salud) suelen exigir
que la clave privada quede bajo su control. Se evaluaron tres modelos: (1) la institución firma con su
propio sistema, (2) CredoSeal custodia la clave (el actual), (3) la clave vive en el HSM de la
institución y CredoSeal sólo pide firmas.

El código ya separa la firma detrás de `SignerBackend` (`create`/`load`/`disable`) y `Signer.sign`,
y cada clave guarda su `backend`: agregar uno nuevo no cambia cómo se construyen ni se verifican las
credenciales.

## Decisión
Se ofrecen **dos opciones comerciales**, no tres:

1. **Gestionada por CredoSeal** (predeterminada, incluida): el modelo actual.
2. **Su clave, su infraestructura** (enterprise, a pedido): agrupa los modelos 1 y 3. La clave privada
   no sale de la institución; CredoSeal envía el *hash* a firmar y recibe la firma.

Se construye **por demanda**, en este orden:

| Fase | Qué | Cuándo |
|---|---|---|
| 1 | **BYOK en AWS**: clave KMS en la cuenta AWS del cliente; CredoSeal asume un rol con permiso sólo de `kms:Sign`/`kms:GetPublicKey` sobre esa clave (ID externo en la confianza). El cliente revoca el acceso cuando quiere. Reutiliza `KmsBackend` con un cliente por rol. ~2-3 días. | Primer cliente enterprise en AWS |
| 2 | **Firmante remoto**: API con mTLS y peticiones firmadas hacia el HSM del cliente (on-premise, Azure Key Vault, Google Cloud KMS), u opcionalmente un agente que instala el cliente y sólo abre conexiones salientes. ~1-2 semanas. | Cliente concreto y pago, con SLA |
| — | **Firma diferida** (OID4VCI *deferred credential*) para quien firme fuera de línea. | Sólo si un cliente lo exige |

No se ofrece el modelo 1 «fuera de línea» como producto: obliga al titular a esperar su credencial.

## Consecuencias y riesgos
- **Disponibilidad compartida**: con clave externa, si el firmante del cliente no responde, CredoSeal
  no puede emitir ni **publicar revocaciones** (las listas de estado también se firman con la clave del
  emisor). Requiere reintentos, alertas, tiempos de espera acotados y un SLA en el contrato.
- **OID4VCI firma al reclamar**: la credencial incluye la clave del titular, así que el firmante externo
  debe estar en línea en ese momento (o usarse la firma diferida).
- **Alta de la clave**: antes de publicarla en el JWKS, la institución prueba posesión firmando un
  desafío; se registra sólo la clave pública y la referencia (ARN o endpoint).
- **Privacidad**: en la opción gestionada CredoSeal sí ve los datos de la credencial al firmarla (se
  guardan cifrados y se borran tras la emisión). «CredoSeal nunca ve el contenido» sólo sería cierto con
  clave externa **y** si el cliente arma lo que se firma; no debe afirmarse en la comunicación comercial.
- **Seguridad**: el firmante remoto es una integración crítica (autenticación mutua, límites, auditoría
  de cada firma con `kid` y hash, nunca el contenido).
