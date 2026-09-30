# ADR-0010 · Panel administrativo estático servido por la API

- Estado: Aceptada · 2026-09-30

## Decisión
Panel en HTML + JavaScript (módulos ES nativos, sin paso de build ni dependencias npm), servido por la propia API bajo `/admin`, mismo origen. Consume sólo la API pública `/v1` con un token de sesión de corta duración (no cookies de terceros, sin CORS).

## Motivos
- Toda la lógica de negocio queda en Python; el panel es un cliente más de la API (garantiza que la API sea completa).
- Sin CloudFront/S3 en el MVP; CSP estricta (`default-src 'self'`).

## Reconsiderar
Si el panel crece (múltiples vistas complejas), migrar a TypeScript con un framework (React/Svelte), build y CloudFront.
