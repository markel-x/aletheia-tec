#!/bin/sh
# Arma pages.js: la función de CloudFront (con sus valores de plantilla) + el adaptador njs.
set -eu
auth=""
if [ -n "${ALETHEIA_SITE_BASIC_AUTH:-}" ]; then
  auth="Basic $(printf %s "$ALETHEIA_SITE_BASIC_AUTH" | base64 | tr -d '\n')"
fi
mkdir -p /tmp/njs
sed -e "s|\${auth}|$auth|" -e "s|\${docs}|true|" /etc/nginx/cloudfront/viewer-request.js > /tmp/njs/pages.js
cat /etc/nginx/edge/adapter.js >> /tmp/njs/pages.js
exec nginx -c /etc/nginx/edge/nginx.conf -g "daemon off;"
