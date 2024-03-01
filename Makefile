.PHONY: all
all: btfhub

#
# make
#

.ONESHELL:
SHELL = /bin/sh

MAKE = make
MAKEFLAGS += --no-print-directory

#
# tools
#

CMD_GIT ?= git
CMD_RM ?= rm
CMD_GO ?= go
CMD_CLANG ?= clang
CMD_STATICCHECK ?= staticcheck

#
# version
#

LAST_GIT_TAG ?= $(shell $(CMD_GIT) describe --tags --match 'v*' 2>/dev/null)
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(LAST_GIT_TAG))

#
# environment
#

DEBUG ?= 0

ifeq ($(DEBUG),1)
	GO_DEBUG_FLAG =
else
	GO_DEBUG_FLAG = -w
endif

#
# variables
#

PROGRAM ?= btfhub

#
# btfhub tool
#

STATIC ?= 0
GO_TAGS =

ifeq ($(STATIC), 1)
    GO_TAGS := $(GO_TAGS),netgo
endif

GO_ENV = CC=$(CMD_CLANG)

SRC_DIRS = ./cmd/ ./pkg/
SRC = $(shell find $(SRC_DIRS) -type f -name '*.go' ! -name '*_test.go')

$(PROGRAM): \
	$(SRC)
#
	$(GO_ENV) $(CMD_GO) build \
		-tags $(GO_TAGS) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-X main.version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/btfhub/

#
# btfhub tests
#

.PHONY: test-unit
test-unit: \
	$(SRC)
#
	$(GO_ENV) \
	$(CMD_GO) test \
		-short \
		-race \
		-v \
		./cmd/... \
		./pkg/...

#
# code checkers
#

.PHONY: check-vet
check-vet: \
#
	$(GO_ENV) \
	$(CMD_GO) vet \
		-tags $(GO_TAGS) \
		./cmd/... \
		./pkg/...

.PHONY: check-staticcheck
check-staticcheck: \
#
	$(GO_ENV) \
	$(CMD_STATICCHECK) -f stylish \
		-tags $(GO_TAGS) \
		./cmd/... \
		./pkg/...

#
# clean
#

.PHONY: clean
clean:
#
	$(CMD_RM) -rf $(PROGRAM)
