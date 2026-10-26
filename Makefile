.PHONY: test build demo

test:
	@test -z "$$(gofmt -l $$(git ls-files '*.go'))" || { gofmt -l $$(git ls-files '*.go'); exit 1; }
	go vet ./...
	go test ./...

build:
	CGO_ENABLED=0 go build -trimpath -o bin/tokening ./cmd/tokening

demo:
	@echo "The Docker demo is not implemented yet. See TODO.md."
	@exit 1
