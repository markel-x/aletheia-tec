#!/bin/sh
# Base de datos separada para las pruebas automatizadas (docker compose run tests).
# Las pruebas aplican y revierten migraciones: nunca deben tocar la base de desarrollo.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
CREATE DATABASE aletheia_test OWNER aletheia_migrate;
EOSQL
