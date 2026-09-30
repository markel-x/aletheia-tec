# ADR-0013 · `tx_code` con HMAC-SHA256 y clave del servidor

- Estado: Aceptada · 2026-09-30 · Reemplaza el uso de Argon2id para `tx_code` (doc 03, `issuance`)

## Contexto
El `tx_code` (6 dígitos, 10⁶ valores) se guardaba con Argon2id (64 MiB, t=3, p=4). La prueba de carga
mostró que ese hash costaba ~51 ms de CPU por oferta y limitaba la creación de ofertas a ~16 req/s por
réplica, con p95 de 560 ms (objetivo 300 ms).

## Análisis
- Frente a **adivinación en línea**, la defensa es el límite de 5 intentos por oferta (y el límite de
  canjes por red): el tipo de hash no influye.
- Frente a una **filtración de la base de datos**, Argon2id no alcanza: 10⁶ × 51 ms ≈ 14 h en un núcleo,
  minutos en un clúster. El espacio es demasiado pequeño para que un KDF lento lo proteja.
- Un **HMAC con clave que no está en la base** hace inútil la filtración de la base sola: sin la clave
  no se puede comprobar ningún candidato. Cuesta ~1 µs.

## Decisión
- `tx_code_hash = "hmac-sha256$v1$" || hex(HMAC-SHA256(clave, issuance_id || ":" || tx_code))`.
  Ligar el `issuance_id` impide reutilizar un hash en otra oferta.
- La clave (`ALETHEIA_TX_CODE_KEY`, ≥ 32 bytes) viene de Secrets Manager en entornos desplegados y la
  aplicación **no arranca** sin ella; en desarrollo se genera en `dev_keys_dir`.
- Migración `0005`: la restricción admite ambos formatos; las ofertas pendientes con Argon2id siguen
  siendo canjeables hasta expirar (máx. 7 días).
- Las **contraseñas de usuario** siguen con Argon2id: son elegidas por personas y ahí el KDF lento sí es
  la defensa adecuada.

## Consecuencias
- Rendimiento de ofertas ×4 (≈ 66 req/s por réplica en la máquina de pruebas), p95 204 ms.
- Rotar la clave invalida los `tx_code` de ofertas pendientes: se hace fuera de horario o se ofrece
  `offer:reset` (runbook).
