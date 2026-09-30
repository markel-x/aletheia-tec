.PHONY: docker-build docker-test docker-demo docker-db docker-db-test docker-up docker-down lock test lint

docker-build:            ## Construye las imágenes test y runtime
	docker compose build

docker-test:             ## ruff + mypy + pytest dentro del contenedor
	docker compose run --rm tests

docker-demo:             ## Demostración del flujo del núcleo en el contenedor runtime
	docker compose run --rm demo

docker-db:               ## Levanta PostgreSQL (sin migrar)
	docker compose up -d db

docker-up:               ## db → migrate → api en http://127.0.0.1:8008
	docker compose up -d api

docker-down:             ## Detiene todo (conserva el volumen de datos)
	docker compose down

lock:                    ## Regenera uv.lock con la misma versión de uv que usa la imagen
	docker run --rm -v "$$PWD:/work" -w /work -e UV_CACHE_DIR=/tmp/uv-cache ghcr.io/astral-sh/uv:0.12.21-python3.13-trixie-slim uv lock

docker-db-test:          ## Pruebas del esquema y de privilegios
	docker compose run --rm db-test

test:                    ## Pruebas en el entorno local (requiere uv sync --group dev)
	PYTHONPATH=src python3 -m pytest -q

lint:
	ruff check src tests && ruff format --check src tests && mypy
