#!/usr/bin/env bash
# L4 release gate (roadmap T12): full issuance against a REAL Pebble CA.
#
#   RUN_PEBBLE_E2E=1 scripts/run_pebble_e2e.sh
#
# Starts pebble + challtestsrv via docker compose, runs
# tests/live_pebble_e2e.rs (production executor set over real HTTPS, DNS-01
# programmed through challtestsrv), and tears the environment down again.
# A skipped run is not a release pass (exit 77).
set -euo pipefail

if [[ "${RUN_PEBBLE_E2E:-}" != "1" ]]; then
  echo "SKIP: RUN_PEBBLE_E2E=1 is required. A skipped Pebble run is not a release pass." >&2
  exit 77
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker is not installed or not on PATH. A skipped Pebble run is not a release pass." >&2
  exit 77
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PEBBLE_DIRECTORY_URL="${PEBBLE_DIRECTORY_URL:-https://127.0.0.1:14000/dir}"
export PEBBLE_CHALLTESTSRV_ADMIN="${PEBBLE_CHALLTESTSRV_ADMIN:-http://127.0.0.1:8055}"
export PEBBLE_E2E_DOMAIN="${PEBBLE_E2E_DOMAIN:-acmex-test.example.com}"

cleanup() {
  docker compose -f "$SCRIPT_DIR/docker-compose.pebble.yml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== starting pebble + challtestsrv"
docker compose -f "$SCRIPT_DIR/docker-compose.pebble.yml" up -d --wait

echo "== waiting for the pebble directory at $PEBBLE_DIRECTORY_URL"
for _ in $(seq 1 30); do
  if curl -ksf "$PEBBLE_DIRECTORY_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "== running the live Pebble E2E (production executor set)"
RUN_PEBBLE_E2E=1 cargo test --test live_pebble_e2e -- --ignored --nocapture

echo "== L4 Pebble E2E PASSED"
