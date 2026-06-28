#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${ROOT_DIR}/target/debug/trace-lens"
SERVICE_PATH="/etc/systemd/system/trace-lens.service"

echo "[1/4] building trace-lens"
source "${HOME}/.cargo/env"
cargo build --manifest-path "${ROOT_DIR}/Cargo.toml"

echo "[2/4] installing binary to /usr/local/bin/trace-lens"
install -m 0755 "${BIN_PATH}" /usr/local/bin/trace-lens

echo "[3/4] installing systemd unit"
install -m 0644 "${ROOT_DIR}/systemd/trace-lens.service" "${SERVICE_PATH}"
systemctl daemon-reload

echo "[4/4] enabling service"
systemctl enable trace-lens.service

echo "install complete"
echo "start with: systemctl start trace-lens.service"
echo "optional tracee install helper: bash ${ROOT_DIR}/scripts/install-tracee.sh"
