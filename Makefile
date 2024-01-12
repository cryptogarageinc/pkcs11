current_dir = $(shell pwd)

golangci_version = v1.55.2
goimports_version = v0.16.0
yamlfmt_version = v0.9.0

.PHONY: all
all: install generate format lint

.PHONY: install
install:
	$(eval BIN:=$(abspath .bin))
	mkdir -p ./.bin
	GOBIN="$(BIN)" go install golang.org/x/tools/cmd/goimports@${goimports_version}
	GOBIN="$(BIN)" go install github.com/golangci/golangci-lint/cmd/golangci-lint@${golangci_version}
	GOBIN="$(BIN)" go install github.com/google/yamlfmt/cmd/yamlfmt@${yamlfmt_version}
	$(call install_local,'go.uber.org/mock', 'go.uber.org/mock/mockgen')

.PHONY: generate
generate:
	$(eval BIN:=$(abspath .bin))
	GOBIN="$(BIN)" go generate ./...

generate-local:
	$(eval BIN:=$(abspath .bin))
	PATH="${PATH}:${BIN}" GOBIN="$(BIN)" go generate ./...

.PHONY: format
format:
	./.bin/goimports -w .
	./.bin/yamlfmt
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

test-api-docker:
	docker run -it --rm -v ${current_dir}:/workspace cryptogarageinc/pkcs11:latest make build test-api

define install_local
	$(eval BIN:=$(abspath .bin))
	grep -E $1 go.mod > module.txt
	cat module.txt | sed 's/^\s*//g' | awk -F' ' '{print $$2}' | sed 's/\s*//g' > version.txt
	GOBIN="$(BIN)" go install $2@`cat version.txt`
	@rm module.txt version.txt
endef
