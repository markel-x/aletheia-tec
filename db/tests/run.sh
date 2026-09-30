#!/bin/sh
# Pruebas del esquema: se ejecutan contra el servicio "db" con el rol propietario
# (esquema y restricciones) y con el rol de la aplicación (privilegios).
set -eu

echo "== esquema y restricciones (aletheia_migrate)"
psql -v ON_ERROR_STOP=1 -q -f /tests/schema.sql

echo "== privilegios del rol de la aplicación (aletheia_app)"
PGUSER=aletheia_app PGPASSWORD="$ALETHEIA_APP_PASSWORD" psql -v ON_ERROR_STOP=1 -q -f /tests/privileges.sql

echo "== OK"
