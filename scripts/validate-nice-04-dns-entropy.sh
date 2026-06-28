#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_PATH="${DB_PATH:-${ROOT_DIR}/db/trace-lens-nice-04.db}"
WORK_DIR="${ROOT_DIR}/runtime/nice-04-dns-entropy"
REPORT_DIR="${WORK_DIR}/exports"
PID=7000

mkdir -p "${WORK_DIR}" "${REPORT_DIR}"
rm -f "${DB_PATH}"

echo "[1/4] initialize validation database"
source "${HOME}/.cargo/env"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- init-db --db-path "${DB_PATH}" >/dev/null

echo "[2/4] ingest dns entropy sample"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  tracee ingest \
  --input "${ROOT_DIR}/samples/tracee-dns-events.ndjson" \
  --db-path "${DB_PATH}" >/dev/null

echo "[3/4] aggregate incident"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  incident "${PID}" \
  --db-path "${DB_PATH}" \
  > "${WORK_DIR}/incident.txt"

echo "[4/4] verify dns entropy IOC and export report"
grep -q "dns_high_entropy_query" "${WORK_DIR}/incident.txt"
grep -q "dns_tunnel_entropy" "${WORK_DIR}/incident.txt"

cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  export report \
  --pid "${PID}" \
  --db-path "${DB_PATH}" \
  --output-dir "${REPORT_DIR}" >/dev/null

echo "scenario: NICE-04 dns entropy"
echo "db_path: ${DB_PATH}"
echo "incident_output: ${WORK_DIR}/incident.txt"
echo "report: ${REPORT_DIR}/incident-${PID}-report.md"
