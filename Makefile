all: lint test build

lint:
	go vet ./...

test:
	go test ./...

fmt:
	go fmt ./...

build:
	go build -trimpath ./cmd/xmpp_blackbox_exporter/xmpp_blackbox_exporter.go

.PHONY: lint test fmt build all
