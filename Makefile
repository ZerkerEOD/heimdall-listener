MODULE  := github.com/ZerkerEOD/heimdall-listener
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%d)
LDFLAGS := -s -w -X $(MODULE)/pkg/version.Version=$(VERSION) -X $(MODULE)/pkg/version.Commit=$(COMMIT) -X $(MODULE)/pkg/version.Date=$(DATE)
GOFLAGS := -trimpath
DIST    := dist

.PHONY: all build test vet tidy clean

all: build

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' ./...

test:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf $(DIST)
