#!/usr/bin/env bash
# One-command box recovery: toolchain deps, rebuild, reinstall, restart m4a-web-client.
# No secrets here: settings come from ~/.config/mail4agent/web-client.env.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${M4A_BIN_DIR:-/usr/local/bin}"
RUN_DIR="${M4A_RUN_DIR:-/tmp/m4a-web-client}"
ENV_FILE="${M4A_ENV_FILE:-$HOME/.config/mail4agent/web-client.env}"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

need=()
command -v ssh >/dev/null || need+=(openssh-client)
command -v pkg-config >/dev/null || need+=(pkg-config)
dpkg -s libssl-dev >/dev/null 2>&1 || need+=(libssl-dev)
if [ ${#need[@]} -gt 0 ]; then $SUDO apt-get update -qq && $SUDO apt-get install -y "${need[@]}"; fi
export PATH="$HOME/.cargo/bin:$PATH"
if ! cargo --version >/dev/null 2>&1; then rustup default stable; fi

export OPENSSL_DIR=/usr OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu OPENSSL_INCLUDE_DIR=/usr/include
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target-keys}"
cd "$REPO"
cargo build --release -p mail4agent-messenger-shell \
  --bin m4a-web-client --bin m4a-send --bin m4a-inbox --bin m4a
for b in m4a-web-client m4a-send m4a-inbox m4a; do
  [ -f "$CARGO_TARGET_DIR/release/$b" ] && $SUDO install -m 0755 "$CARGO_TARGET_DIR/release/$b" "$BIN_DIR/$b"
done

mkdir -p "$RUN_DIR"
if [ -f "$RUN_DIR/run.pid" ] && kill -0 "$(cat "$RUN_DIR/run.pid")" 2>/dev/null; then
  kill "$(cat "$RUN_DIR/run.pid")"; sleep 2
fi
pkill -x m4a-web-client 2>/dev/null || true; sleep 1
set -a; [ -f "$ENV_FILE" ] && . "$ENV_FILE"; set +a
nohup "$BIN_DIR/m4a-web-client" >>"$RUN_DIR/run.log" 2>&1 &
echo $! >"$RUN_DIR/run.pid"
for _ in $(seq 1 60); do grep -q "open ok" "$RUN_DIR/run.log" && break; sleep 1; done
grep -q "open ok" "$RUN_DIR/run.log" && echo "m4a-web-client up (pid $(cat "$RUN_DIR/run.pid"))" \
  || { echo "no 'open ok' yet; see $RUN_DIR/run.log"; exit 1; }
