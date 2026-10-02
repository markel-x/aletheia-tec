# POC en Android: Google Wallet

El titular recibe la credencial como pase de Google Wallet desde la misma página `/claim/{oferta}` que
Apple Wallet; el QR del pase se verifica igual (firma + revocación en vivo). Decisión: ADR-0017.

## 1. Requisitos (sin costo)

1. **Proyecto de Google Cloud** con la **Google Wallet API** habilitada (APIs y servicios → Biblioteca).
2. **Cuenta de servicio** en ese proyecto (IAM → Cuentas de servicio → Crear). En *Claves* → *Agregar clave*
   → **JSON**: el archivo descargado es `ALETHEIA_GOOGLE_WALLET_SERVICE_ACCOUNT`. Guárdelo como secreto; no lo
   suba al repositorio.
3. **Cuenta de emisor** en la [consola de Google Pay & Wallet](https://pay.google.com/business/console) →
   Google Wallet API. Anote el **Issuer ID** (`ALETHEIA_GOOGLE_WALLET_ISSUER_ID`).
4. En la consola, **Usuarios** → invitar el correo de la cuenta de servicio (`…@….iam.gserviceaccount.com`)
   con acceso al emisor, para que pueda crear clases y objetos.
5. **Modo demo:** mientras Google no apruebe el acceso de publicación, sólo las cuentas de Google habilitadas
   como prueba en la consola pueden guardar los pases. Agregue la cuenta del teléfono Android de la prueba.
6. Un teléfono **Android** con Google Wallet, y la API en una URL pública HTTPS (el logo del pase,
   `/wallet/logo.png`, lo descarga Google).

## 2. Configuración en AWS

```bash
aws secretsmanager create-secret --name aletheia-staging/google-wallet \
  --secret-string file://service-account.json
```

```bash
cd infra/terraform && terraform apply -var environment=staging -var domain_name=aletheia.soyuzlabs.com \
  -var google_wallet_issuer_id=<issuer-id> -var google_wallet_secret_arn=<arn-del-secreto>
```

El `apply` registra una revisión de la tarea `api` con las dos variables; el siguiente despliegue la usa.
Sin las variables, la página del titular no muestra la opción de Google Wallet.

## 3. Guion de la prueba

1. Panel → **Credenciales** → nueva oferta. Envíe el enlace al teléfono Android y el código por otro medio.
2. En el teléfono: **Agregar a Google Wallet** → código → Google Wallet muestra el pase → *Guardar*.
   El panel muestra la credencial `issued` con entrega *Google Wallet*.
3. Con otro teléfono, escanee el QR del pase → **Credencial válida**.
4. Panel → **Revocar** → vuelva a escanear → **Credencial NO válida**. (El pase en Google Wallet no cambia
   de aspecto: la revocación se ve al verificar.)

## 4. Qué queda comprobado sin Google real (automático)

`tests/test_google_pass.py` simula la API: token OAuth con el JWT de la cuenta de servicio (alcance
`wallet_object.issuer`), clase creada una vez, objeto con datos y QR, enlace `savetowallet` firmado que sólo
referencia el objeto, fallo de Google sin emitir (la oferta sigue disponible), reintento con objeto
existente (`PUT`), verificación y revocación del QR, canal desactivado sin configuración.
