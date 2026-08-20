.PHONY: install build typecheck test lint doctor

install:
	UV_CACHE_DIR=.uv-cache uv sync --locked --dev
	npm ci

build:
	UV_CACHE_DIR=.uv-cache uv run --locked python -m openbachelor_ios build

typecheck:
	npm run typecheck

test:
	UV_CACHE_DIR=.uv-cache uv run --locked python -m pytest -q

lint:
	UV_CACHE_DIR=.uv-cache uv run --locked ruff check openbachelor_ios tests

doctor:
	UV_CACHE_DIR=.uv-cache uv run --locked openbachelor-ios doctor
