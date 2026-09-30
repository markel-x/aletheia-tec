.PHONY: docker-build docker-test docker-demo docker-db docker-db-test test lint

docker-build:            ## Construye las imágenes test y runtime
	docker compose build

docker-test:             ## ruff + mypy + pytest dentro del contenedor
	docker compose run --rm tests

docker-demo:             ## Demostración del flujo del núcleo en el contenedor runtime
	docker compose run --rm demo

docker-db:               ## Levanta PostgreSQL con el esquema inicial
	docker compose up -d db

docker-db-test:          ## Pruebas del esquema y de privilegios
	docker compose run --rm db-test

test:                    ## Pruebas en el entorno local (requiere cryptography, PyJWT, pytest)
	PYTHONPATH=src python3 -m pytest -q

lint:
	ruff check src tests && ruff format --check src tests && mypy
