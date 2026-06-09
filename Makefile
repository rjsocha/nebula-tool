GO ?= go
BINARY ?= nebula-tool
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO_FILES := $(wildcard *.go)

.PHONY: all build clean install

all: $(BINARY)

build: $(BINARY)

$(BINARY): $(GO_FILES) go.mod go.sum Makefile
	$(GO) build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o $(BINARY) .

clean:
	rm -f $(BINARY)

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BINARY) $(DESTDIR)$(BINDIR)/$(BINARY)
