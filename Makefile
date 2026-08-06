SHELL := /bin/sh

POSTGRES_HOST_PORT ?= 5432
REDIS_HOST_PORT ?= 6379

.PHONY: tidy tidy-check fmt fmt-check vet lint test test-race deps test-integration build vuln validate-openapi validate-k8s validate run up down logs migrate

tidy:
	go mod tidy

tidy-check:
	go mod tidy -diff

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	test -z "$$(gofmt -l .)"

vet:
	go vet ./...

lint:
	golangci-lint run --timeout=5m

test:
	go test -timeout=2m ./...

test-race:
	go test -race -timeout=2m ./...

deps:
	POSTGRES_PORT=$(POSTGRES_HOST_PORT) REDIS_PORT=$(REDIS_HOST_PORT) docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --wait postgres redis

test-integration: deps
	AUTH_SESSION_HASH_KEY='01234567890123456789012345678901' POSTGRES_URL='postgres://auth:auth@localhost:$(POSTGRES_HOST_PORT)/auth?sslmode=disable' REDIS_ADDRESS='localhost:$(REDIS_HOST_PORT)' REDIS_KEY_PREFIX='auth:integration:' go test -race -tags=integration ./integration -count=1 -timeout=5m

build:
	go build ./cmd/api ./cmd/migrate

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

validate-openapi:
	openapi-spec-validator api/openapi.yaml

validate-k8s:
	docker run --rm -v "$$(pwd):/work:ro" ghcr.io/yannh/kubeconform:v0.7.0@sha256:85dbef6b4b312b99133decc9c6fc9495e9fc5f92293d4ff3b7e1b30f5611823c -strict -summary /work/deploy/kubernetes

validate: tidy-check fmt-check vet lint test validate-openapi validate-k8s

run:
	go run ./cmd/api

up:
	test -f .env || cp .env.example .env
	docker compose up --build -d --wait

down:
	docker compose down

logs:
	docker compose logs -f api

migrate:
	go run ./cmd/migrate
