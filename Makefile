current_dir = $(shell pwd)

.PHONY: all
all: install generate format lint

.PHONY: install
install:
	$(eval BIN:=$(abspath .bin))
	mkdir -p ./.bin
	GOBIN="$(BIN)" go install golang.org/x/tools/cmd/goimports@v0.8.0
	GOBIN="$(BIN)" go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.53.3
	$(call install_local,'github.com/golang/mock', 'github.com/golang/mock/mockgen')

.PHONY: generate
generate:
	$(eval BIN:=$(abspath .bin))
	GOBIN="$(BIN)" go generate ./...

.PHONY: format
format:
	./.bin/goimports -w .
	go mod tidy

.PHONY: lint
lint:
	./.bin/golangci-lint run

.PHONY: build
build:
	go mod download
	go build ./...

.PHONY: test
test:
	go mod download
	go test -short -v -p 1 -count=1 .

test-api:
	go mod download
	cd apis/pkcs11; go test -short -v -p 1 -count=1 .

setup-docker:
	docker build -t cryptogarageinc/pkcs11:latest -f Dockerfile .

test-docker:
	docker run -it --rm -v ${current_dir}:/workspace cryptogarageinc/pkcs11:latest make build test test-api

define install_local
	$(eval BIN:=$(abspath .bin))
	grep -E $1 go.mod > module.txt
	cat module.txt | sed 's/^\s*//g' | awk -F' ' '{print $$2}' | sed 's/\s*//g' > version.txt
	GOBIN="$(BIN)" go install $2@`cat version.txt`
	@rm module.txt version.txt
endef
