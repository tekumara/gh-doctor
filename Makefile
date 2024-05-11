MAKEFLAGS += --warn-undefined-variables
SHELL = /bin/bash -o pipefail
.DEFAULT_GOAL := help
.PHONY: help build

## display help message
help:
	@awk '/^##.*$$/,/^[~\/\.0-9a-zA-Z_-]+:/' $(MAKEFILE_LIST) | awk '!(NR%2){print $$0p}{p=$$0}' | awk 'BEGIN {FS = ":.*?##"}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' | sort

## build snapshot release
release:
	goreleaser release --snapshot --skip=publish --clean

## format
fmt:
	go fmt ./...

## lint
lint:
	(which golangci-lint || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.58.1)
	golangci-lint run

## update go.mod to match the source code in the module
tidy:
	go mod tidy

## examines Go source code and reports suspicious constructs
vet:
	go vet ./...

## run tests
test:
	go test -cover ./...
