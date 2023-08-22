current_dir = $(shell pwd)
GO_EXE=`go env GOEXE`

.PHONY: install
install:
	cd ../..; $(MAKE) install

.PHONY: format
format:
	../../.bin/goimports -w .
	../../.bin/yamlfmt
	go mod tidy

.PHONY: lint
lint:
	../../.bin/golangci-lint run

.PHONY: build
build:
	go mod download
	go build -o bip32util${GO_EXE} main.go dependency.go
