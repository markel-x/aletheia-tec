# ADR-0008 · PostgreSQL como único almacén: sin SQS ni Redis en el MVP

- Estado: Aceptada · 2026-09-30

## Decisión
- Sin SQS: todas las operaciones del MVP son síncronas y cortas. Tareas periódicas (expirar ofertas, purgar nonces y datos pendientes, retención de auditoría) se ejecutan con `aletheia maintenance` como tarea ECS programada (EventBridge Scheduler — único servicio añadido a la tabla de referencia; justificado por ser el mecanismo nativo para tareas ECS periódicas).
- Sin ElastiCache: rate limiting por ventana fija en PostgreSQL (`INSERT … ON CONFLICT DO UPDATE`), nonces e idempotencia en tablas con restricciones únicas. Caché del Status List Token en memoria de proceso.

## Cuándo reconsiderar
- Webhooks con reintentos o emisión masiva → SQS.
- Más de ~500 req/s sostenidas en rate limiting → Redis/ElastiCache.
