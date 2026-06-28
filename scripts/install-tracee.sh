#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRACEE_BIN_DEST="${TRACEE_BIN_DEST:-/usr/local/bin/tracee}"
TRACEE_TMP_DIR="${TRACEE_TMP_DIR:-/tmp/tracee-install}"
TRACEE_TARBALL="${TRACEE_TARBALL:-/tmp/tracee-x86_64.v0.24.1.tar.gz}"
TRACEE_SRC_TARBALL="${TRACEE_SRC_TARBALL:-/tmp/tracee-src-v0.24.1-codeload.tar.gz}"
TRACEE_SRC_DIR="${TRACEE_SRC_DIR:-/tmp/tracee-src}"

mkdir -p "${TRACEE_TMP_DIR}"

install_binary() {
  local src="$1"
  install -m 0755 "${src}" "${TRACEE_BIN_DEST}"
  "${TRACEE_BIN_DEST}" version || "${TRACEE_BIN_DEST}" --help >/dev/null || true
}

install_from_release_tarball() {
  local tarball="$1"
  rm -rf "${TRACEE_TMP_DIR:?}/release"
  mkdir -p "${TRACEE_TMP_DIR}/release"
  tar -xzf "${tarball}" -C "${TRACEE_TMP_DIR}/release"
  local bin
  bin="$(find "${TRACEE_TMP_DIR}/release" -type f -name tracee | head -n 1)"
  if [[ -z "${bin}" ]]; then
    echo "tracee binary not found in release tarball: ${tarball}" >&2
    exit 1
  fi
  install_binary "${bin}"
}

install_from_source_tree() {
  local src_dir="$1"
  if [[ ! -d "${src_dir}" ]]; then
    echo "source directory not found: ${src_dir}" >&2
    exit 1
  fi

  pushd "${src_dir}" >/dev/null
  if [[ -f Makefile ]]; then
    make tracee
  else
    go build -o dist/tracee ./cmd/tracee
  fi
  local bin
  bin="$(find . -type f \( -path './dist/tracee' -o -path './build/tracee' -o -name tracee \) | head -n 1)"
  popd >/dev/null

  if [[ -z "${bin}" ]]; then
    echo "failed to build tracee from source: ${src_dir}" >&2
    exit 1
  fi

  install_binary "${src_dir}/${bin#./}"
}

install_from_source_tarball() {
  local tarball="$1"
  rm -rf "${TRACEE_TMP_DIR:?}/src"
  mkdir -p "${TRACEE_TMP_DIR}/src"
  tar -xzf "${tarball}" -C "${TRACEE_TMP_DIR}/src"
  local extracted
  extracted="$(find "${TRACEE_TMP_DIR}/src" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "${extracted}" ]]; then
    echo "failed to extract source tarball: ${tarball}" >&2
    exit 1
  fi
  install_from_source_tree "${extracted}"
}

if [[ -x "${TRACEE_BIN_DEST}" ]]; then
  echo "tracee already installed at ${TRACEE_BIN_DEST}"
  "${TRACEE_BIN_DEST}" version || "${TRACEE_BIN_DEST}" --help >/dev/null || true
  exit 0
fi

if [[ -f "${TRACEE_TARBALL}" ]]; then
  echo "installing tracee from release tarball: ${TRACEE_TARBALL}"
  install_from_release_tarball "${TRACEE_TARBALL}"
  exit 0
fi

if [[ -d "${TRACEE_SRC_DIR}" ]]; then
  echo "installing tracee from source tree: ${TRACEE_SRC_DIR}"
  install_from_source_tree "${TRACEE_SRC_DIR}"
  exit 0
fi

if [[ -f "${TRACEE_SRC_TARBALL}" ]]; then
  echo "installing tracee from source tarball: ${TRACEE_SRC_TARBALL}"
  install_from_source_tarball "${TRACEE_SRC_TARBALL}"
  exit 0
fi

cat >&2 <<EOF
no usable Tracee input found.
supported inputs:
  - release tarball: ${TRACEE_TARBALL}
  - source tree: ${TRACEE_SRC_DIR}
  - source tarball: ${TRACEE_SRC_TARBALL}
EOF
exit 1
