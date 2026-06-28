#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRACEE_BIN="${TRACEE_BIN:-/usr/local/bin/tracee}"
DB_PATH="${DB_PATH:-${ROOT_DIR}/db/trace-lens-h1-05.db}"
WORK_DIR="${ROOT_DIR}/runtime/h1-05-cron"
TRACEE_OUTPUT="${WORK_DIR}/tracee.ndjson"
REPORT_DIR="${WORK_DIR}/exports"
CRON_FILE="/etc/cron.d/trace-lens-h1-05"

mkdir -p "${WORK_DIR}" "${REPORT_DIR}"
rm -f "${TRACEE_OUTPUT}" "${DB_PATH}"

if [[ ! -x "${TRACEE_BIN}" ]]; then
  echo "tracee binary not found or not executable: ${TRACEE_BIN}" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${TRACEE_PID:-}" ]]; then
    kill "${TRACEE_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${CRON_FILE}"
}
trap cleanup EXIT

echo "[1/6] start Tracee capture"
"${TRACEE_BIN}" \
  --policy "${ROOT_DIR}/configs/tracee-policy.yaml" \
  --output json \
  --output option:parse-arguments \
  > "${TRACEE_OUTPUT}" 2> "${WORK_DIR}/tracee.stderr" &
TRACEE_PID=$!

for _ in $(seq 1 20); do
  if [[ -s "${TRACEE_OUTPUT}" ]]; then
    break
  fi
  sleep 1
done

if [[ ! -s "${TRACEE_OUTPUT}" ]]; then
  echo "tracee did not produce output in time" >&2
  exit 1
fi

sleep 2

SCENARIO_CMD="printf '* * * * * root /bin/true\\n' > ${CRON_FILE}"

echo "[2/6] execute adversary command: ${SCENARIO_CMD}"
bash -lc "${SCENARIO_CMD}"

sleep 2
rm -f "${CRON_FILE}"
sleep 1
kill "${TRACEE_PID}" >/dev/null 2>&1 || true
wait "${TRACEE_PID}" || true
unset TRACEE_PID

echo "[3/6] initialize scenario database"
source "${HOME}/.cargo/env"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- init-db --db-path "${DB_PATH}" >/dev/null

echo "[4/6] ingest Tracee output"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  tracee ingest \
  --input "${TRACEE_OUTPUT}" \
  --db-path "${DB_PATH}" >/dev/null

PID_QUERY="select json_extract(payload_json,'$.processId') \
from raw_events \
where source_kind='tracee' \
  and event_name='security_file_open' \
  and json_extract(payload_json,'$.processName') = 'bash' \
  and payload_json like '%/etc/cron.d/trace-lens-h1-05%' \
  and payload_json like '%O_WRONLY%' \
order by observed_at desc limit 1;"
ROOT_PID="$(sqlite3 "${DB_PATH}" "${PID_QUERY}")"

if [[ -z "${ROOT_PID}" ]]; then
  echo "failed to locate the root pid for H1-05 scenario" >&2
  exit 1
fi

echo "[5/6] aggregate incident for pid ${ROOT_PID}"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  incident "${ROOT_PID}" \
  --db-path "${DB_PATH}" \
  > "${WORK_DIR}/incident.txt"

echo "[6/6] export report and timeline"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  export report \
  --pid "${ROOT_PID}" \
  --db-path "${DB_PATH}" \
  --output-dir "${REPORT_DIR}" >/dev/null

cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  export timeline \
  --pid "${ROOT_PID}" \
  --db-path "${DB_PATH}" \
  --output-dir "${REPORT_DIR}" >/dev/null

echo "scenario: H1-05 cron"
echo "db_path: ${DB_PATH}"
echo "tracee_output: ${TRACEE_OUTPUT}"
echo "root_pid: ${ROOT_PID}"
echo "incident_output: ${WORK_DIR}/incident.txt"
echo "report: ${REPORT_DIR}/incident-${ROOT_PID}-report.md"
echo "timeline: ${REPORT_DIR}/incident-${ROOT_PID}-timeline.json"
