VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w
CODESIGN ?= false
BINARY_SERVER := gsearch-server
BINARY_INSTALLER := gsearch-installer
DIST := dist

.PHONY: all build clean release release-check release-dry-run publish install test vet

RELEASE_CHANNEL ?= all
RELEASE_FLAGS ?=

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_SERVER) ./cmd/server/
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_INSTALLER) ./cmd/installer/

install: build
	mkdir -p ~/.gsearch
	cp $(BINARY_SERVER) ~/.gsearch/$(BINARY_SERVER)
	@xattr -d com.apple.quarantine ~/.gsearch/$(BINARY_SERVER) 2>/dev/null || true
	@echo "installed to ~/.gsearch/$(BINARY_SERVER)"

clean:
	rm -f $(BINARY_SERVER) $(BINARY_INSTALLER)
	rm -rf $(DIST)

test:
	go test ./cmd/server/ -count=1 -timeout 30s
	go test ./cmd/installer/ -count=1 -timeout 30s

vet:
	go vet ./...

# Release never depends on clean: existing artifacts are preserved.
release:
	@bash scripts/release.sh build --dist "$(DIST)" $(if $(filter true,$(CODESIGN)),--codesign,) $(RELEASE_FLAGS)

release-check:
	@bash scripts/release.sh check $(RELEASE_FLAGS)

release-dry-run:
	@bash scripts/release.sh build --dry-run --dist "$(DIST)" $(RELEASE_FLAGS)

# Explicit publication only; select one channel to resume a partial release.
publish:
	@bash scripts/release.sh publish --channel "$(RELEASE_CHANNEL)" --dist "$(DIST)" $(RELEASE_FLAGS)
