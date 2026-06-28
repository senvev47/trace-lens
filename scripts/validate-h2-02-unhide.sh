#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_PATH="${DB_PATH:-${ROOT_DIR}/db/trace-lens-h2-02.db}"
WORK_DIR="${ROOT_DIR}/runtime/h2-02-unhide"
FAKE_BIN_DIR="${WORK_DIR}/fake-bin"

mkdir -p "${WORK_DIR}" "${FAKE_BIN_DIR}"
rm -f "${DB_PATH}"

cat > "${FAKE_BIN_DIR}/timeout" <<'EOF'
#!/usr/bin/env bash
cat <<'OUT'
Unhide 20211016
Used options:
[*]Searching for Hidden processes through comparison of results of system calls, proc, dir and ps
Hidden process found: /proc/4242 mismatch
suspicious TCP/31337 hidden port
OUT
EOF
chmod +x "${FAKE_BIN_DIR}/timeout"

cat > "${FAKE_BIN_DIR}/bpftool" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${FAKE_BIN_DIR}/bpftool"

echo "[1/3] initialize validation database"
source "${HOME}/.cargo/env"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- init-db --db-path "${DB_PATH}" >/dev/null

echo "[2/3] run ring0 check with injected unhide output"
PATH="${FAKE_BIN_DIR}:$PATH" cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  ring0 check \
  --db-path "${DB_PATH}" \
  > "${WORK_DIR}/ring0-check.txt"

echo "[3/3] verify unhide findings were inserted"
COUNT="$(sqlite3 "${DB_PATH}" "select count(*) from ring0_findings where detector='unhide' and finding_type='hidden_process';")"
if [[ "${COUNT}" -lt 2 ]]; then
  echo "expected at least 2 unhide hidden_process findings, got ${COUNT}" >&2
  exit 1
fi

echo "scenario: H2-02 unhide"
echo "db_path: ${DB_PATH}"
echo "ring0_output: ${WORK_DIR}/ring0-check.txt"
echo "unhide_findings: ${COUNT}"
