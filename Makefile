VERSION ?= dev

.PHONY: build install clean fmt lint check

build:
	go build -ldflags="-s -w -X main.version=$(VERSION)" -o ssm ./cmd/ssm

install: build
	cp ssm ~/.local/bin/ssm

clean:
	rm -f ssm

fmt:
	gofmt -w .

lint:
	golangci-lint run ./...

check:
	go run ./cmd/verify ci
