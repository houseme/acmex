#!/usr/bin/env bash
# L5 release gate (roadmap T19): controlled Let's Encrypt staging validation.
#
#   RUN_LE_STAGING=1 scripts/run_le_staging.sh
#
# The Rust test performs preflight checks and writes a non-secret manifest under
# target/le-staging. Preflight-only output is not a release pass.
set -euo pipefail

if [[ "${RUN_LE_STAGING:-}" != "1" ]]; then
  echo "SKIP: RUN_LE_STAGING=1 is required. A skipped LE staging run is not a release pass." >&2
  exit 77
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "FAIL: cargo is required for scripts/run_le_staging.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
export ACMEX_LE_STAGING_DIRECTORY_URL="${ACMEX_LE_STAGING_DIRECTORY_URL:-https://acme-staging-v02.api.letsencrypt.org/directory}"
export ACMEX_LE_STAGING_ARTIFACT_DIR="${ACMEX_LE_STAGING_ARTIFACT_DIR:-$REPO_DIR/target/le-staging/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$ACMEX_LE_STAGING_ARTIFACT_DIR"

{
  printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'git_sha=%s\n' "$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
  printf 'directory_url=%s\n' "$ACMEX_LE_STAGING_DIRECTORY_URL"
  printf 'scenarios=%s\n' "${ACMEX_LE_STAGING_SCENARIOS:-all}"
} >"$ACMEX_LE_STAGING_ARTIFACT_DIR/environment.txt"

echo "== running LE staging preflight and evidence gate"
if ! RUN_LE_STAGING=1 cargo test --test le_staging -- --ignored --nocapture 2>&1 \
  | tee "$ACMEX_LE_STAGING_ARTIFACT_DIR/cargo-test-le-staging.log"; then
  echo "== LE staging gate FAILED; artifacts: $ACMEX_LE_STAGING_ARTIFACT_DIR" >&2
  exit 1
fi

if [[ -x "$SCRIPT_DIR/secret_scan.sh" ]]; then
  "$SCRIPT_DIR/secret_scan.sh"
fi

echo "== LE staging preflight completed; this is not a release pass until full issuance evidence is attached"
echo "== artifacts: $ACMEX_LE_STAGING_ARTIFACT_DIR"
