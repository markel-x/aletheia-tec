# ADR-0005 · Estado y revocación con Token Status List generado a demanda

- Estado: Aceptada · 2026-09-30

## Decisión
- Listas de 131 072 entradas, 1 bit, índice aleatorio sin reutilización.
- Fuente de verdad: tabla `credential_status` en PostgreSQL.
- `GET /status-lists/{id}` construye, comprime (zlib/DEFLATE) y firma el Status List Token a demanda con `ttl=300`, `exp=iat+86400`; respuesta cacheable (`Cache-Control: max-age=300`). Caché en proceso por `(list_id, version)`.
- Revocar = una transacción que cambia estado, incrementa `status_list.version` y registra auditoría. No hay "publicación" separada que pueda fallar a mitad.
- Revocación irreversible e idempotente: revocar una credencial revocada devuelve el mismo resultado (200, sin nuevo evento).

## Por qué no bitstring precalculado en S3/CloudFront
Añade un paso de publicación asíncrono y un estado intermedio inconsistente. Reconsiderar si el volumen de verificaciones externas lo justifica (el token es de ≈ algunos KB y cacheable).

## Consecuencias
- Verificadores externos pueden ver el estado anterior hasta `ttl` (300 s). Documentado como política.
- Firmar a demanda consume `kms:Sign` como máximo una vez por lista, versión y réplica de la API.
