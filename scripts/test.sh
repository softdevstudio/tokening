#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p test/results/local
unformatted=$(find cmd internal -name '*.go' -exec gofmt -l {} +)
if [ -n "$unformatted" ]; then
  echo "Run gofmt on these files:"
  echo "$unformatted"
  exit 1
fi
python3 -m unittest discover -s scripts -p '*_test.py'
go vet ./...
go test -count=1 -json ./... | tee test/results/local/tests.jsonl
