.PHONY: build run docker-up docker-down docker-build test macos-helper restart restart-helper restart-all repo-update repo-push

DOCKER_COMPOSE ?= $(shell if command -v docker-compose >/dev/null 2>&1; then echo docker-compose; else echo "docker compose"; fi)
COMPOSE_FILE ?= docker-compose.yml
GIT_REMOTE ?= origin
GIT_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)

build:
	go build -o bin/server ./cmd/server

run:
	go run ./cmd/server

docker-build:
	docker build -t password-manager-go:local .

docker-up:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) up --build

docker-down:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) down

restart:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) down
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) up --build

restart-helper:
	-pkill -f "macos-unlock --server"
	./bin/macos-unlock --server > /tmp/macos-unlock.log 2>&1 &

restart-all: restart restart-helper

repo-update:
	git fetch --all --prune --tags
	git pull --ff-only $(GIT_REMOTE) $(GIT_BRANCH)
repo-push:
	@if [ -z "$(m)" ]; then echo "Usage: make repo-push m='commit message'"; exit 1; fi
	git add -A
	@if git diff --cached --quiet; then \
		echo "No staged changes to commit. Skipping commit."; \
	else \
		git commit -m "$(m)"; \
	fi
	@git push $(GIT_REMOTE) $(GIT_BRANCH) || { \
		echo "Push failed. Check Git auth (SSH key/token) and remote URL."; \
		exit 1; \
	}
test:
	go test ./...

macos-helper:
	mkdir -p bin
	swiftc -framework LocalAuthentication -framework Security -framework Network -o bin/macos-unlock ./macos-unlock/main.swift
