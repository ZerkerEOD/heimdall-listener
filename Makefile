MODULE  := github.com/ZerkerEOD/heimdall-listener
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%d)
LDFLAGS := -s -w -X $(MODULE)/pkg/version.Version=$(VERSION) -X $(MODULE)/pkg/version.Commit=$(COMMIT) -X $(MODULE)/pkg/version.Date=$(DATE)
GOFLAGS := -trimpath
DIST    := dist
FYNE    ?= fyne
MINGW   ?= x86_64-w64-mingw32-gcc

.PHONY: all build test vet tidy clean dist checksums \
        cli-linux-amd64 cli-linux-arm64 cli-windows-amd64 gui-linux gui-windows tools

all: build

## Development ---------------------------------------------------------------

build:            ## build both binaries for the host (GUI needs cgo + libpcap)
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' ./...

test:             ## run all tests with the race detector
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf $(DIST) cmd/heimdall-listener/heimdall-listener cmd/heimdall-listener/*.exe cmd/heimdall-listener/*.tar.xz

tools:            ## install the fyne packaging tool
	go install fyne.io/tools/cmd/fyne@latest

## Release artifacts ----------------------------------------------------------

cli-linux-amd64:   ## static, no libpcap needed on the target
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/heimdall-cli-linux-amd64 ./cmd/heimdall-cli

cli-linux-arm64:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/heimdall-cli-linux-arm64 ./cmd/heimdall-cli

cli-windows-amd64:  ## pure Go; needs Npcap installed on the target
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/heimdall-cli-windows-amd64.exe ./cmd/heimdall-cli

gui-linux:          ## needs libpcap-dev, libgl1-mesa-dev, xorg-dev
	@mkdir -p $(DIST)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/heimdall-listener-linux-amd64 ./cmd/heimdall-listener

gui-windows:        ## cross-compiled with mingw; icon + no console via fyne package
	@mkdir -p $(DIST)
	cd cmd/heimdall-listener && CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=$(MINGW) \
		$(FYNE) package -os windows --release --app-version $(patsubst v%,%,$(VERSION)) \
		--name heimdall-listener
	mv cmd/heimdall-listener/heimdall-listener.exe $(DIST)/heimdall-listener-windows-amd64.exe

checksums:
	cd $(DIST) && sha256sum * > SHA256SUMS

dist: clean cli-linux-amd64 cli-linux-arm64 cli-windows-amd64 gui-linux gui-windows checksums  ## everything
	@ls -la $(DIST)
