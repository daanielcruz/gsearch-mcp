VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w
CODESIGN ?= false
BINARY_SERVER := gsearch-server
BINARY_INSTALLER := gsearch-installer
DIST := dist

.PHONY: all build clean release install test vet

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

release: clean
	@mkdir -p $(DIST)
	@echo "building server..."
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_SERVER)-darwin-arm64      ./cmd/server/
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_SERVER)-darwin-amd64      ./cmd/server/
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_SERVER)-linux-amd64       ./cmd/server/
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_SERVER)-linux-arm64       ./cmd/server/
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_SERVER)-windows-amd64.exe ./cmd/server/
	@echo "building installer..."
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_INSTALLER)-darwin-arm64      ./cmd/installer/
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_INSTALLER)-darwin-amd64      ./cmd/installer/
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_INSTALLER)-linux-amd64       ./cmd/installer/
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_INSTALLER)-linux-arm64       ./cmd/installer/
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY_INSTALLER)-windows-amd64.exe ./cmd/installer/
ifeq ($(CODESIGN),true)
	@codesign -s - $(DIST)/$(BINARY_SERVER)-darwin-arm64
	@codesign -s - $(DIST)/$(BINARY_SERVER)-darwin-amd64
	@codesign -s - $(DIST)/$(BINARY_INSTALLER)-darwin-arm64
	@codesign -s - $(DIST)/$(BINARY_INSTALLER)-darwin-amd64
	@echo "binaries signed (ad-hoc)"
endif
	@echo "binaries in $(DIST)/"
