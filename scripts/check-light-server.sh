#!/usr/bin/env bash
# Checks the light server: built with every optional feature off (no hash-id rooms, no presence, no
# remote media, no thumbnails), so the Matrix-side pieces are not compiled or linked. Code stays;
# features switch it off. No secrets, no network.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo build -p mail4agent-server -p mail4agent-server-bin --no-default-features
cargo test -p mail4agent-server --no-default-features
cargo test -p mail4agent-server-bin --no-default-features --bin mail4agent-server-bin
# The light binary must not link the Matrix core crate or the image crate.
if cargo tree -p mail4agent-server-bin --no-default-features -e normal | grep -E "m4a-matrix-core|image v"; then
  echo "light server still links a Matrix-side crate" >&2; exit 1
fi
echo "light server ok"
