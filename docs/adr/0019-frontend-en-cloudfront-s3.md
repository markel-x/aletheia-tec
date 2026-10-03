# ADR-0019 · Frontend en S3 + CloudFront, separado de la API

- Estado: Aceptada · 2026-10-03 (paso 2 pendiente de `terraform apply` en staging)

## Contexto
La API (FastAPI en ECS) servía también las páginas: inicio, panel, páginas del titular (reclamo,
verificación), página del emisor y documentación. Son archivos estáticos (HTML + módulos ES sin build)
que obtienen sus datos de la API: ocupaban tareas de la API, no se cacheaban cerca del visitante y cada
cambio de texto exigía una imagen nueva.

## Decisión
- Las páginas y sus recursos se publican en un **bucket S3 privado** y se sirven con **CloudFront**
  (acceso por OAC). No hace falta otra instancia: ninguna página necesita servidor.
- **Un solo dominio** para frontend y API: CloudFront envía las rutas de la API (`/v1/*`, `/public/*`,
  OpenID4VCI/VP, `/.well-known/*`, listas de estado, `/claim-info/*`, `/claim/*/*`, …) al ALB y el resto a
  S3. El `iss` de las credenciales emitidas, los QR y las ofertas ya apuntan a este dominio y no pueden
  cambiar; además el panel llama a la API sin CORS ni cookies entre dominios.
- Una **CloudFront Function** hace lo que hacía el router de páginas: URLs limpias (`/claim/<id>` →
  `claim.html`, …), 404 para lo demás, y el acceso restringido temporal (HTTP Basic) con la misma
  credencial. La CSP y las cabeceras de seguridad pasan a *response headers policies*.
- El **ALB sólo acepta a CloudFront**: grupo de seguridad con la lista de prefijos de CloudFront y regla
  del listener que exige una cabecera secreta de origen (`X-Origin-Verify`); lo demás recibe 403.
- La **IP del visitante** llega en `CloudFront-Viewer-Address` (el ALB sólo ve el borde de CloudFront):
  la API la usa para los límites por red (`ALETHEIA_CLIENT_IP_HEADER`), confiable porque el ALB rechaza
  lo que no viene de CloudFront.
- El pipeline publica el frontend en S3 (tipos y caché por extensión) e invalida CloudFront, después de
  actualizar la API.
- En desarrollo y en las pruebas la API sigue sirviendo las páginas (`ALETHEIA_SERVE_FRONTEND`, por
  defecto `true`): un solo proceso, mismas rutas.

## Puesta en marcha
1. `frontend_on_cloudfront = false`: `terraform apply` crea bucket y distribución; cargar `FRONTEND_BUCKET`
   y `CDN_DISTRIBUTION_ID` (salida `deploy_config`) en el entorno de GitHub y desplegar: el frontend queda
   en S3. El DNS sigue en el ALB; se puede probar la distribución por su dominio `*.cloudfront.net`
   enviando `Host` (o con `curl --resolve`).
2. `frontend_on_cloudfront = true`: `terraform apply` mueve el DNS a CloudFront, cierra el ALB y la API
   deja de servir páginas (redesplegar para que la tarea tome el entorno nuevo).

## Consecuencias
- Páginas desde el borde más cercano (incluida Sudamérica: `PriceClass_All`), sin costo de cómputo.
- Dos superficies a mantener coherentes: rutas de la función ↔ archivos (`tests/test_api_only.py`
  comprueba que cada HTML tiene ruta) y CSP de Terraform ↔ CSP de la API en desarrollo.
- La credencial del acceso restringido queda en el código de la función y en el estado de Terraform;
  aceptable por ser temporal (se elimina al abrir el sitio).
- Sin logs estándar de CloudFront ni WAF por ahora; las peticiones a la API siguen en los logs del ALB.
