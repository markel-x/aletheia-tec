# Prueba de carga

`run.py` mide los tres endpoints con objetivo en [docs/00 §4](../docs/00-alcance-y-supuestos.md)
contra la pila de compose. El cliente usa el núcleo de Aletheia para las claves del titular; la API es
la imagen `runtime` real con PostgreSQL.

```bash
# El límite de /oid4vci/token por red (60 / 15 min) se eleva sólo para la prueba:
ALETHEIA_OID4VCI_TOKEN_RATE_LIMIT=1000000 docker compose up -d api
docker compose run --rm -v "$PWD/loadtest:/loadtest:ro" -e ALETHEIA_PASSWORD=... \
  tests python /loadtest/run.py --duration 30 --workers 8
```

## Resultados (2026-09-30)

Entorno: Docker Desktop en un Mac (arm64), **4 CPU y 7,7 GiB para todos los contenedores**
(cliente, API y PostgreSQL compiten por la misma CPU). Una réplica de la API (uvicorn, 1 proceso),
firmante `local_dev`. **No es staging**: los valores indican órdenes de magnitud y cuellos de botella,
no la capacidad en AWS.

| Escenario | Hilos | req/s | p50 | p95 | p99 | Objetivo p95 | |
|---|---|---|---|---|---|---|---|
| `POST /v1/credentials` (oferta) | 8 | 66,7 | 119 ms | **204 ms** | 234 ms | < 300 ms | ✅ |
| `POST /oid4vci/credential` (firma incl.) | 8 | 29,6* | 66 ms | **91 ms** | 104 ms | < 600 ms | ✅ |
| `POST /v1/verifications` (emisor alojado) | 8 | 69,5 | 75 ms | **91 ms** | 102 ms | < 300 ms | ✅ |
| `GET /status-lists/{id}` (caché) | 8 | 508,8 | 15 ms | 24 ms | 33 ms | — | |
| `POST /v1/credentials` | 16 | 64,6 | 293 ms | 443 ms | 505 ms | < 300 ms | ❌ saturado |
| `POST /oid4vci/credential` | 16 | 29,0* | 83 ms | 113 ms | 139 ms | < 600 ms | ✅ |
| `POST /v1/verifications` | 16 | 66,9 | 155 ms | 190 ms | 210 ms | < 300 ms | ✅ |

\* Cada iteración de `issue` crea además la oferta, canjea el código y pide el nonce: el rendimiento es
el del flujo completo; la latencia es sólo la del Credential Endpoint.

Sin errores en ningún escenario (0 respuestas no esperadas).

## Lectura

- **Hallazgo corregido.** La primera medición dio p95 = 560 ms para crear ofertas con 8 hilos y un techo
  de ~16 req/s: el `tx_code` se guardaba con Argon2id (64 MiB, t=3, p=4 → 51 ms de CPU por oferta).
  Se sustituyó por HMAC-SHA256 con clave del servidor ([ADR-0013](../docs/adr/0013-tx-code-hmac.md)):
  el rendimiento de ofertas pasó de ~16 a ~66 req/s (×4) y el p95 a 204 ms.
- **Capacidad por réplica ≈ 65 ofertas/s ≈ 70 verificaciones/s** en esta máquina. Con 16 hilos el
  rendimiento no sube y la latencia crece: es cola por CPU, no un endpoint lento. En AWS la respuesta es
  escalar tareas: autoescalado por CPU al 60 % (`infra/terraform/compute.tf`) y alarma de CPU
  sostenida > 85 %.
- **KMS no está en estas cifras**: `kms:Sign` añade una llamada de red por emisión (típicamente
  decenas de ms). El margen hasta 600 ms es amplio, pero debe medirse en staging.
- **Pendiente en staging**: repetir con 2 tareas Fargate, RDS real y KMS; objetivo de la prueba
  según docs/00 §4 con carga sostenida, no picos de 30 s.
