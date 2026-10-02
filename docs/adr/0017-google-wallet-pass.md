# ADR-0017 · Entrega como pase de Google Wallet con QR verificable

- Estado: Aceptada · 2026-10-02

## Contexto
Tras el pase de Apple Wallet (ADR-0016) se pidió el equivalente para Android. Google Wallet, como Apple
Wallet, no acepta credenciales verificables de terceros por OpenID4VCI; lo que un emisor puede agregar son
**pases** de la API de Google Wallet. Diferencias con Apple:
- El pase **vive en los servidores de Google**: el emisor crea una *clase* y un *objeto* con la API REST
  (`walletobjects.googleapis.com`) autenticado con una **cuenta de servicio**, y el titular lo guarda con un
  enlace `https://pay.google.com/gp/v/save/<JWT>` firmado por esa cuenta.
- Sin costo de alta ni por pase. Una cuenta de emisor nueva está en **modo demo** (sólo cuentas de prueba
  pueden guardar pases) hasta que Google aprueba el acceso de publicación.

## Decisión
- Nuevo canal de entrega **`google_pass`** (migración 0009), en la misma página `/claim/{offer_id}` y con el
  mismo `tx_code`, límite de intentos y canje único por oferta que Apple Wallet.
- Al canjear, Aletheia firma el mismo **SD-JWT VC sin `cnf`** que para Apple, cierra la emisión y crea el
  objeto `genericObject` (`<issuer>.<public_id>`) en la clase compartida `<issuer>.aletheia_credential`
  (creada en el primer uso). El JWT del enlace **sólo referencia el objeto por id**: los datos no viajan en
  la URL y no hay límite de tamaño del enlace.
- La llamada a Google ocurre **dentro de la transacción** de la emisión: si Google falla, la emisión no se
  confirma y la oferta sigue disponible. Si el objeto ya existe (reintento tras un fallo posterior), se
  reemplaza (`PUT`) con la credencial recién firmada.
- El **QR del pase es el mismo** que el de Apple (`/v#<credencial>`) y se verifica igual, en vivo.
- `POST /claim/{offer_id}/google-pass` responde JSON con el enlace y la página navega con JavaScript: la CSP
  `form-action 'self'` impide que un formulario redirija a otro origen, y se mantiene estricta.
- El logo del pase es una URL pública de Aletheia (`/wallet/logo.png`), que Google descarga.
- Configuración: `ALETHEIA_GOOGLE_WALLET_ISSUER_ID` y `ALETHEIA_GOOGLE_WALLET_SERVICE_ACCOUNT` (JSON de la
  clave; en AWS desde Secrets Manager, variables Terraform `google_wallet_issuer_id` y
  `google_wallet_secret_arn`). Sin ellas el canal está desactivado; no hay modo de desarrollo simulado.

## Consecuencias y límites
- Mismo **modelo de confianza al portador** que el pase de Apple (ADR-0016): quien ve el QR ve los datos.
- **Privacidad:** a diferencia de Apple, los datos del pase y la credencial del QR quedan **almacenados en
  Google** como encargado del emisor. Debe constar en la información al titular.
- El objeto **no se marca como revocado** en Google al revocar (pendiente: `PATCH state=INACTIVE`); el QR
  refleja la revocación al instante.
- La API de Google es una dependencia en línea del canje por este canal; los otros canales no dependen de ella.
- Las pruebas simulan la API (`httpx.MockTransport`); no hay prueba automática contra Google real.
