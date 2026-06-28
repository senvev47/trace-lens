#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRACEE_BIN="${TRACEE_BIN:-/usr/local/bin/tracee}"
TRACEE_POLICY="${ROOT_DIR}/configs/tracee-policy.yaml"
TRACEE_OUTPUT="${ROOT_DIR}/runtime/tracee-live.ndjson"
TRACE_LENS_DB="${ROOT_DIR}/db/trace-lens.db"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-20}"

mkdir -p "${ROOT_DIR}/runtime"

if [[ ! -x "${TRACEE_BIN}" ]]; then
  echo "tracee binary not found or not executable: ${TRACEE_BIN}" >&2
  exit 1
fi

if [[ ! -f "${TRACEE_POLICY}" ]]; then
  echo "tracee policy not found: ${TRACEE_POLICY}" >&2
  exit 1
fi

echo "[1/4] capturing Tracee events for ${CAPTURE_SECONDS}s"
timeout "${CAPTURE_SECONDS}" \
  "${TRACEE_BIN}" \
  --policy "${TRACEE_POLICY}" \
  --signatures-dir /tmp/tracee-install/release/dist/signatures \
  --output json \
  --output option:parse-arguments \
  > "${TRACEE_OUTPUT}" || true

echo "[2/4] captured output: ${TRACEE_OUTPUT}"
wc -l "${TRACEE_OUTPUT}" || true

echo "[3/4] ingesting into Trace Lens"
source "${HOME}/.cargo/env"
cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  tracee ingest \
  --input "${TRACEE_OUTPUT}" \
  --db-path "${TRACE_LENS_DB}"

echo "[4/4] recent tracee events in sqlite"
sqlite3 "${TRACE_LENS_DB}" \
  "select event_name, count(*) from raw_events where source_kind='tracee' group by event_name order by 2 desc;"
