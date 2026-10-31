#!/bin/sh
# Rerun the flight recorder case studies with the latest released Linux binary.
# Local only: a stub CMS on 127.0.0.1:18090, tokening on 127.0.0.1:18080/18081.
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
