#!/bin/sh
# Roles de la base de datos. Se ejecuta una sola vez, al inicializar el volumen.
#
#   aletheia_app  : rol de la API. DML sobre las tablas de negocio; en audit_event
#                   sólo INSERT y SELECT (registro append-only, ADR/doc 03).
#   aletheia_migrate (= POSTGRES_USER): propietario del esquema; lo usará Alembic.
set -eu

: "${ALETHEIA_APP_PASSWORD:?ALETHEIA_APP_PASSWORD no definida}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_password="$ALETHEIA_APP_PASSWORD" <<'EOSQL'
CREATE ROLE aletheia_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
EOSQL
