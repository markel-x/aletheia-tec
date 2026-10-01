# POC en iPhone: Apple Wallet y wallet OpenID4VCI

Flujo completo de punta a punta con un iPhone real. Dos caminos, desde la misma oferta:

| Camino | Qué recibe el titular | Cómo se verifica |
|---|---|---|
| **A. Apple Wallet** | Un pase en la app Wallet con los datos y un QR | Cualquiera escanea el QR con la cámara → página de Aletheia (firma + revocación en vivo) |
| **B. Wallet OpenID4VCI** | La credencial SD-JWT VC ligada a una clave del teléfono | El verificador pide la credencial por OID4VP (QR en el panel) y el titular elige qué datos compartir |

## 1. Requisitos

1. **URL pública con HTTPS.** El iPhone no llega a `127.0.0.1`, y Wallet/las wallets exigen HTTPS.
   Para la prueba se usa un túnel temporal (Cloudflare Quick Tunnel, sin cuenta):
   ```bash
   docker compose --profile tunnel up -d tunnel
   docker compose logs tunnel | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com'
   ```
   Con esa URL, reinicie la API para que la use como origen público (emisor, enlaces, QR):
   ```bash
   ALETHEIA_PUBLIC_BASE_URL=https://<subdominio>.trycloudflare.com docker compose up -d api
   ```
   El túnel expone la API a Internet mientras esté activo: deténgalo al terminar
   (`docker compose --profile tunnel stop tunnel`). Las credenciales emitidas con una URL quedan ligadas a
   ella (`iss`): si el túnel cambia de URL, emita credenciales nuevas.

2. **Camino A:** cuenta de **Apple Developer Program**, un **Pass Type ID** (`pass.<dominio-invertido>.…`)
   y su certificado:
   - developer.apple.com → Certificates, Identifiers & Profiles → Identifiers → **Pass Type IDs** → crear.
   - Crear el certificado del Pass Type ID (requiere una CSR), descargarlo e importarlo; exportar
     certificado y clave a PEM.
   - Descargar **Apple WWDR G4** (Apple PKI) en PEM.
   - Configurar `ALETHEIA_PASS_TYPE_IDENTIFIER`, `ALETHEIA_PASS_TEAM_IDENTIFIER`, `ALETHEIA_PASS_CERT_PEM`,
     `ALETHEIA_PASS_KEY_PEM`, `ALETHEIA_PASS_WWDR_PEM` y reiniciar la API.
   - Sin esto, el pase se firma con un certificado de prueba y **el iPhone no lo agregará**.

3. **Camino B:** una wallet OpenID4VCI con soporte de SD-JWT VC instalada en el iPhone. Algunas exigen que
   el emisor y el verificador estén en su lista de confianza o firmen con certificados X.509 de una CA
   reconocida (perfil HAIP); en ese caso use su modo de desarrollo o agregue los certificados de prueba.

## 2. Guion de la prueba

1. Panel → **Credenciales** → nueva oferta con la plantilla publicada. Anote el código de 6 dígitos.
2. Envíe el QR (o el enlace `…/claim/…`) al iPhone y, por otro medio, el código.
3. **Camino A:** en el iPhone, abra el enlace → *Agregar a Apple Wallet* → código → Safari muestra la hoja
   de Wallet → *Agregar*. El panel muestra la credencial como `issued` con entrega *Apple Wallet*.
4. Con otro teléfono, escanee el QR del pase con la cámara → **Credencial válida** con los datos.
5. Panel → **Revocar** la credencial → vuelva a escanear el QR → **Credencial NO válida** (revocada).
6. **Camino B:** nueva oferta → en el iPhone, *Abrir en mi wallet* → la wallet pide el código → guarda la
   credencial. Panel → **Verificación** → *Solicitar a un wallet* → el titular escanea con su wallet, acepta
   compartir lo pedido → el panel muestra **valid** con los datos divulgados.

## 3. Qué queda comprobado sin iPhone (automático)

- `tests/test_apple_pass.py`: página del titular, intentos de código, `.pkpass` (estructura, manifiesto SHA-1,
  firma PKCS#7 con el certificado del Pass Type ID), cierre de la emisión, un solo canal por oferta, bloqueo,
  verificación pública (válida, revocada, alterada, credencial vinculada rechazada).
- Firma del pase verificada con **OpenSSL** (`smime -verify`), independiente de nuestro código.
- `interop/run.mjs`: el camino B con una implementación independiente de wallet (`@sd-jwt/sd-jwt-vc`, `jose`).
