# Build variables
PACKAGE = github.com/l7mp/stunner-auth-service
BUILD_DIR ?= bin/
LDFLAGS += -s -w
GOARGS = -trimpath

ifeq (${VERBOSE}, 1)
ifeq ($(filter -v,${GOARGS}),)
	GOARGS += -v
endif
endif

.PHONY: all
all: build

.PHONY: generate
generate: ## OpenAPI codegen
	go generate ./...

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: generate fmt vet
	go test ./... -v

.PHONY: lint
lint: ## Run golangci-lint against code.
	golangci-lint run

##@ Build

.PHONY: build
build: generate fmt vet build-bin

.PHONY: build-bin
bin: build-bin
build-bin:
	go build ${GOARGS} -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/authd .

.PHONY: clean
clean:
	rm -rf ${BUILD_DIR}
