current_dir = $(shell pwd)

.PHONY: format
format:
	../../.bin/goimports -w .
	go mod tidy

.PHONY: lint
lint:
	../../.bin/golangci-lint run

.PHONY: build
build:
	go mod download
	go build -o bip32util main.go dependency.go

build-win:
	go mod download
	go build -o bip32util.exe main.go dependency.go
