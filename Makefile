BIN        := rdp-screenshotter
PKG        := github.com/x-stp/rdp-screenshotter-go
CMDS       := ./cmd/rdp-screenshotter ./cmd/credssp-test
GOFLAGS    ?= -trimpath
LDFLAGS    ?= -s -w
TESTFLAGS  ?= -race -count=1

.PHONY: all build install test vet fmt lint cover tidy clean help

all: build

build: ## go build all commands
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/rdp-screenshotter
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o credssp-test ./cmd/credssp-test

install: ## go install the rdp-screenshotter CLI
	go install $(GOFLAGS) -ldflags '$(LDFLAGS)' $(PKG)/cmd/rdp-screenshotter

test: ## go test with race detector
	go test $(TESTFLAGS) ./...

vet: ## go vet
	go vet ./...

fmt: ## gofmt -s -w
	gofmt -s -w .

lint: ## go vet + golangci-lint (falls back to staticcheck, then skip)
	go vet ./...
	@if which golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; \
	elif which staticcheck >/dev/null 2>&1; then staticcheck ./...; \
	else echo 'golangci-lint/staticcheck not installed; skip'; fi

cover: ## go test with coverage
	go test -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

tidy: ## go mod tidy + verify
	go mod tidy
	go mod verify

clean: ## remove built binaries and coverage
	rm -f $(BIN) credssp-test coverage.out

help: ## show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
