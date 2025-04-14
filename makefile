# Go binary and module
GO := go

# Binary names and source dirs
SERVER_BIN := zcomm-server
CLIENT_BIN := zcomm-client
SERVER_DIR := ./cmd/server
CLIENT_DIR := ./cmd/client

# Default target
all: build-server build-client

## ---------- SERVER ----------

build-server:
	$(GO) build -o $(SERVER_BIN) $(SERVER_DIR)

run-server:
	$(GO) run $(SERVER_DIR)

## ---------- CLIENT ----------

build-client:
	$(GO) build -o $(CLIENT_BIN) $(CLIENT_DIR)

run-client:
	$(GO) run $(CLIENT_DIR)

## ---------- UTILITIES ----------

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

test:
	$(GO) test ./...

clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN)

.PHONY: all build-server run-server build-client run-client fmt tidy test clean
