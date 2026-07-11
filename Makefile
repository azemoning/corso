.PHONY: build build-agent build-ctl docker-build test lint

BINARY_AGENT=corso
BINARY_CTL=corso-ctl
IMAGE=corso:latest
GO=go

build: build-agent build-ctl

build-agent:
	CGO_ENABLED=0 $(GO) build -o bin/$(BINARY_AGENT) ./cmd/corso/

build-ctl:
	CGO_ENABLED=0 $(GO) build -o bin/$(BINARY_CTL) ./cmd/corso-ctl/

docker-build:
	docker build -t $(IMAGE) .

test:
	$(GO) test ./... -v -count=1

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
