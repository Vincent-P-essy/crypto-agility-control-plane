.PHONY: install test lint typecheck verify scan benchmark oqs docker

install:
	uv sync --extra dev --frozen

test:
	uv run --frozen pytest --cov --cov-report=term-missing

lint:
	uv run --frozen ruff check .
	uv run --frozen ruff format --check .

typecheck:
	uv run --frozen mypy

verify: lint typecheck test

scan:
	uv run --frozen crypto-agility scan fixtures/inventory --out reports/generated

oqs:
	./scripts/build-liboqs.sh .local/oqs

benchmark:
	OQS_INSTALL_PATH=$(CURDIR)/.local/oqs LD_LIBRARY_PATH=$(CURDIR)/.local/oqs/lib uv run --frozen crypto-agility benchmark --iterations 25 --out reports/generated/benchmark.json

docker:
	docker build --pull -t crypto-agility-control-plane:local .
