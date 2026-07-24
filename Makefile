GO ?= go
NEBULA_VERSION ?= v1.11.0
BINARY ?= nebula-tool
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO_FILES := $(wildcard *.go)

.PHONY: all build clean install update-deps

all: $(BINARY)

build: $(BINARY)

$(BINARY): $(GO_FILES) go.mod go.sum Makefile
	$(GO) build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o $(BINARY) .

go.mod go.sum: Makefile
	$(GO) get github.com/slackhq/nebula@$(NEBULA_VERSION)
	$(GO) mod tidy

# Upgrade direct dependencies (auto-detected from the module, Nebula excluded
# since it is pinned via NEBULA_VERSION) to their latest minor/patch releases.
update-deps:
	$(GO) get -u $$($(GO) list -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}}{{end}}' all | grep -v '^github.com/slackhq/nebula$$')
	$(GO) mod tidy

clean:
	rm -f $(BINARY)

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BINARY) $(DESTDIR)$(BINDIR)/$(BINARY)
