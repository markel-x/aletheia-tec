# ADR-0009 · Minimización y retención de datos personales

- Estado: Aceptada · 2026-09-30

## Decisión
- El registro de emisión (`issuance`) guarda: plantilla y versión, `vct`, `kid`, índice de estado, fechas, estado, `holder_reference` opcional (identificador **opaco** provisto por el emisor, p. ej. su ID interno; nunca un correo) y `holder_key_thumbprint`.
- Los **atributos de la credencial** se guardan sólo en `issuance_pending_claims`, cifrados con envelope encryption (KMS en producción; clave local en desarrollo), mientras la oferta está pendiente. Se borran al emitir, expirar o cancelar la oferta.
- No se almacena la credencial firmada. Si el titular la pierde, el emisor debe reemitir (con nueva oferta).
- Contacto del titular (correo/teléfono) **no** se almacena en el MVP: el emisor entrega enlace y `tx_code` por sus propios canales. (Envío por correo desde Aletheia: pendiente.)
- Logs: nunca payloads de credenciales, disclosures, tokens, `tx_code`, claves ni atributos; sólo IDs internos, `request_id`, códigos de resultado.
- Hash de atributos personales **no** se considera anonimización y no se usa como sustituto.
