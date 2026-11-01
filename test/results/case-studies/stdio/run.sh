#!/bin/sh
# Rerun the stdio case study with the latest released Linux binary and the
# real filesystem MCP server (npx, @modelcontextprotocol/server-filesystem).
# Local only: tokening on 127.0.0.1:18180/18181, a temporary notes folder.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
arch=$(uname -m); case "$arch" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; esac
base=https://github.com/softdevstudio/tokening/releases/latest/download
curl -fsSL -o "$bin/tokening-linux-$arch.tar.gz" "$base/tokening-linux-$arch.tar.gz"
curl -fsSL -o "$bin/SHA256SUMS" "$base/SHA256SUMS"
(cd "$bin" && grep " tokening-linux-$arch.tar.gz\$" SHA256SUMS | sha256sum -c - && tar xzf "tokening-linux-$arch.tar.gz")
python3 "$here/run.py" "$bin/tokening"
