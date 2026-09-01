#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUN_PEBBLE_E2E:-}" != "1" ]]; then
  echo "SKIP: RUN_PEBBLE_E2E=1 is required. A skipped Pebble run is not a release pass." >&2
  exit 77
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker is not installed or not on PATH. A skipped Pebble run is not a release pass." >&2
  exit 77
fi

if [[ -z "${PEBBLE_DIRECTORY_URL:-}" ]]; then
  echo "SKIP: set PEBBLE_DIRECTORY_URL to a prepared Pebble directory endpoint." >&2
  exit 77
fi

echo "Pebble directory: ${PEBBLE_DIRECTORY_URL}"
echo "Running local fake-adapter gates while full Pebble issuance remains environment-provided."
cargo test --test fault_injection_matrix -- --nocapture
