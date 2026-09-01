BINARIES := vestad vesta-agent vesta-proxy vesta-init vesta
PLATFORMS := linux/amd64 linux/arm64

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# CGO stays off: every binary must be a static one that runs on any Linux we target,
# including the vesta-init shim bind-mounted into images that have no libc at all.
export CGO_ENABLED = 0

LDFLAGS := -s -w \
	-X getvesta.sh/internal/version.Version=$(VERSION) \
	-X getvesta.sh/internal/version.Commit=$(COMMIT) \
	-X getvesta.sh/internal/version.Date=$(DATE)

.PHONY: all build test vet fmt check clean release proto tools

all: check build

build: $(addprefix bin/,$(BINARIES))

bin/%:
	@mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/$*

# Every store-touching test runs against both backends, on every commit rather than
# nightly, so the less-used one cannot rot (ARCHITECTURE §2.5).
test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: vet
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt found unformatted files"; exit 1)
	$(MAKE) test

release:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		for b in $(BINARIES); do \
			echo "  $$os/$$arch $$b"; \
			mkdir -p bin/$$os-$$arch; \
			GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
				-o bin/$$os-$$arch/$$b ./cmd/$$b || exit 1; \
		done; \
	done

# protoc is not vendored. Install it and the Go plugins with `make tools`, or generate in
# a container; the .proto files in proto/ are the contract either way.
proto:
	@command -v protoc >/dev/null || { echo "protoc not found: run 'make tools' or see proto/README.md"; exit 1; }
	protoc --go_out=. --go_opt=module=getvesta.sh \
	       --go-grpc_out=. --go-grpc_opt=module=getvesta.sh \
	       proto/*.proto

tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "protoc itself: brew install protobuf | apt install protobuf-compiler"

clean:
	rm -rf bin
