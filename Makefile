.PHONY: docker-build docker-test docker-demo test lint

docker-build:            ## Construye las imágenes test y runtime
	docker compose build

docker-test:             ## ruff + mypy + pytest dentro del contenedor
	docker compose run --rm tests

docker-demo:             ## Demostración del flujo del núcleo en el contenedor runtime
	docker compose run --rm demo

test:                    ## Pruebas en el entorno local (requiere cryptography, PyJWT, pytest)
	PYTHONPATH=src python3 -m pytest -q

lint:
	ruff check src tests && ruff format --check src tests && mypy
