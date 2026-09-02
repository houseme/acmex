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
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
export PEBBLE_DIRECTORY_URL="${PEBBLE_DIRECTORY_URL:-https://127.0.0.1:14000/dir}"
export PEBBLE_CHALLTESTSRV_ADMIN="${PEBBLE_CHALLTESTSRV_ADMIN:-http://127.0.0.1:8055}"
export PEBBLE_E2E_DOMAIN="${PEBBLE_E2E_DOMAIN:-acmex-test.example.com}"
export PEBBLE_E2E_ARTIFACT_DIR="${PEBBLE_E2E_ARTIFACT_DIR:-$REPO_DIR/target/pebble-e2e/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$PEBBLE_E2E_ARTIFACT_DIR"
PEBBLE_TRUST_ANCHOR_TEMP="${PEBBLE_TRUST_ANCHOR_PEM_FILE:-$(mktemp "${TMPDIR:-/tmp}/acmex-pebble-root.XXXXXX.pem")}"
export PEBBLE_TRUST_ANCHOR_PEM_FILE="$PEBBLE_TRUST_ANCHOR_TEMP"

cleanup() {
  docker compose -f "$SCRIPT_DIR/docker-compose.pebble.yml" logs --no-color >"$PEBBLE_E2E_ARTIFACT_DIR/compose.log" 2>&1 || true
  docker compose -f "$SCRIPT_DIR/docker-compose.pebble.yml" down -v >/dev/null 2>&1 || true
  if [[ "$PEBBLE_TRUST_ANCHOR_TEMP" == "${TMPDIR:-/tmp}"/acmex-pebble-root.*.pem ]]; then
    rm -f "$PEBBLE_TRUST_ANCHOR_TEMP"
  fi
}
trap cleanup EXIT

cat >"$PEBBLE_E2E_ARTIFACT_DIR/environment.txt" <<EOF
timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
directory_url=$PEBBLE_DIRECTORY_URL
challtestsrv_admin=$PEBBLE_CHALLTESTSRV_ADMIN
domain=$PEBBLE_E2E_DOMAIN
git_sha=$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
EOF

echo "== starting pebble + challtestsrv"
docker compose -f "$SCRIPT_DIR/docker-compose.pebble.yml" up -d --wait

if [[ ! -s "$PEBBLE_TRUST_ANCHOR_PEM_FILE" ]]; then
  echo "== extracting Pebble trust anchor to $PEBBLE_TRUST_ANCHOR_PEM_FILE"
  docker compose -f "$SCRIPT_DIR/docker-compose.pebble.yml" cp \
    pebble:/test/certs/pebble.minica.pem "$PEBBLE_TRUST_ANCHOR_PEM_FILE"
fi

echo "== waiting for the pebble directory at $PEBBLE_DIRECTORY_URL"
ready=0
for _ in $(seq 1 30); do
  if curl -ksf "$PEBBLE_DIRECTORY_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != "1" ]]; then
  echo "FAIL: pebble directory did not become ready at $PEBBLE_DIRECTORY_URL" >&2
  exit 1
fi

echo "== running the live Pebble E2E (production executor set)"
if ! RUN_PEBBLE_E2E=1 cargo test --test live_pebble_e2e -- --ignored --nocapture 2>&1 \
  | tee "$PEBBLE_E2E_ARTIFACT_DIR/cargo-test-live-pebble-e2e.log"; then
  echo "== L4 Pebble E2E FAILED; artifacts: $PEBBLE_E2E_ARTIFACT_DIR" >&2
  exit 1
fi

echo "== L4 Pebble E2E PASSED"
echo "== artifacts: $PEBBLE_E2E_ARTIFACT_DIR"
