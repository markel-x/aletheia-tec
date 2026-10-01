# ADR-0016 · Entrega como pase de Apple Wallet con QR verificable

- Estado: Aceptada · 2026-09-30

## Contexto
Se pidió integrar la credencial con **Apple Wallet**. Investigación (septiembre 2026):
- Apple Wallet **no** implementa OpenID4VCI ni SD-JWT VC y **no permite que terceros emitan credenciales
  verificables** en Wallet. Los documentos de identidad de Wallet son mdoc (ISO 18013-5) emitidos por
  autoridades asociadas con Apple.
- Safari 26 (Digital Credentials API, `org-iso-mdoc`) permite a un sitio **leer** IDs de Wallet, previo
  registro en Apple Business Connect: sirve para verificar identidad, no para certificados de curso.
- Lo que un tercero sí puede poner en Wallet son **pases** (`.pkpass`), firmados con un certificado de Pass
  Type ID de una cuenta de Apple Developer Program.

## Decisión
- Nuevo canal de entrega **`apple_pass`** junto a OID4VCI. El QR de la oferta abre una página HTTPS
  (`/claim/{offer_id}`) donde el titular elige: **Agregar a Apple Wallet** o abrir su wallet OpenID4VCI.
  Ambos exigen el `tx_code`, con el mismo límite de intentos; una oferta se canjea por un solo canal.
- Al canjear por pase, Aletheia firma un **SD-JWT VC sin `cnf`** (no hay clave del titular en Wallet) con
  todos los claims visibles, cierra la emisión (`issued`, `delivery = apple_pass`, borra los claims
  pendientes) y devuelve un `.pkpass` genérico: `pass.json`, imágenes, `manifest.json` (SHA-1) y firma
  PKCS#7 desacoplada con el certificado del Pass Type ID y la cadena WWDR.
- El **QR del pase** es `https://{host}/v#<credencial>`: la credencial viaja en el **fragmento**, que el
  navegador no envía al servidor; la página la manda en el cuerpo a `POST /public/pass-verifications`, que
  verifica firma, vigencia y **estado de revocación en vivo**, sólo para emisores alojados en la instancia.
  Ni la URL ni los registros contienen datos personales.
- La verificación pública **rechaza credenciales con `cnf`** (`holder_bound_credential`): una credencial
  OID4VCI copiada no puede hacerse pasar por un pase.
- Sin certificado de Apple configurado, en desarrollo se firma con una CA **de prueba** (estructura
  idéntica, sujeto con UID/OU como Apple); el iPhone rechaza esos pases. En entornos desplegados sin
  certificado, el canal se desactiva.

## Consecuencias y límites
- **Modelo de confianza distinto** al de la wallet OID4VCI: el pase es un comprobante *al portador* (como
  un certificado en papel con QR). Quien ve el QR ve los datos; no prueba que quien lo muestra sea el
  titular ni permite divulgación selectiva. La página de verificación lo advierte ("compruebe que los datos
  coinciden con la persona"). Para presentación con privacidad y prueba de posesión, OID4VCI/OID4VP.
- El pase **no se actualiza solo** al revocar (no se implementa el servicio web de PassKit ni APNs): el
  QR sí refleja la revocación al instante.
- QR de ~1 KB (credencial completa): denso pero legible desde pantalla.
- Requiere cuenta de Apple Developer (99 USD/año), un Pass Type ID y su certificado:
  `ALETHEIA_PASS_TYPE_IDENTIFIER`, `ALETHEIA_PASS_TEAM_IDENTIFIER`, `ALETHEIA_PASS_CERT_PEM`,
  `ALETHEIA_PASS_KEY_PEM`, `ALETHEIA_PASS_WWDR_PEM` (Apple WWDR G4).
