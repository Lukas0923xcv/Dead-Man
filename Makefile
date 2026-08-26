.PHONY: help setup up down restart logs status test build

COMPOSE ?= docker compose

help:
	@echo "Available commands:"
	@echo "  make setup   - Automated setup: Installs Docker (if missing) and starts container"
	@echo "  make up      - Start SecureVault with Docker Compose in background"
	@echo "  make down    - Stop SecureVault containers"
	@echo "  make restart - Restart SecureVault container"
	@echo "  make logs    - View real-time container logs"
	@echo "  make status  - Check container status and health"
	@echo "  make test    - Run Python test suite"
	@echo "  make build   - Rebuild Docker image"

setup:
	chmod +x setup.sh && ./setup.sh

up:
	mkdir -p data/vault
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart

logs:
	$(COMPOSE) logs -f

status:
	$(COMPOSE) ps

build:
	$(COMPOSE) build

test:
	python3 -m unittest discover -s tests -v
