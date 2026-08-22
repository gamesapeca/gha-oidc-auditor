.PHONY: all build test lint clean

BINARY_NAME := gha-oidc

all: test build

build:
	go build -o bin/$(BINARY_NAME) ./cmd/gha-oidc

test:
	go test -v -cover ./...

lint:
	go vet ./...

clean:
	go clean
	rm -rf bin/
