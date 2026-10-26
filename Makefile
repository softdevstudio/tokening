.PHONY: test build demo

test:
	bash scripts/test.sh

build:
	CGO_ENABLED=0 go build -trimpath -o bin/tokening ./cmd/tokening

demo:
	python3 demo/run.py
