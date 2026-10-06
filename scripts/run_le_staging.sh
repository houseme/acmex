#!/usr/bin/env bash
# L5 release gate (roadmap T19): controlled Let's Encrypt staging validation.
#
#   RUN_LE_STAGING=1 scripts/run_le_staging.sh
#
# The Rust test performs scenario-aware preflight checks and writes a non-secret
# manifest under target/le-staging. `ACMEX_LE_STAGING_SCENARIOS=directory` is a
# non-mutating CA directory smoke; issuance scenarios still require caller-owned
# validation assets. Preflight-only output is not a release pass.
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
run_cargo_gate() {
  local name="$1"
  shift
  echo "== running $name"
  if ! "$@" 2>&1 | tee "$ACMEX_LE_STAGING_ARTIFACT_DIR/${name}.log"; then
    echo "== $name FAILED; artifacts: $ACMEX_LE_STAGING_ARTIFACT_DIR" >&2
    exit 1
  fi
}

scenario_selected() {
  local needle="$1"
  local raw="${ACMEX_LE_STAGING_SCENARIOS:-all}"
  if [[ "$raw" == "all" ]]; then
    return 0
  fi

  local item
  IFS=',' read -ra items <<<"$raw"
  for item in "${items[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

run_cargo_gate le-staging-preflight \
  cargo test --test le_staging -- --ignored --nocapture

if scenario_selected http-01 || scenario_selected dns-01 || \
  scenario_selected renewal || scenario_selected profile; then
  run_cargo_gate le-staging-issuance \
    cargo test --test le_staging_issuance -- --ignored --nocapture
fi

if scenario_selected ip-http-01 || scenario_selected ip-tls-alpn-01; then
  if [[ -z "${ACMEX_LE_STAGING_IP_SCENARIOS:-}" ]]; then
    ip_scenarios=()
    if scenario_selected ip-http-01; then
      ip_scenarios+=(ipv4-http-01 ipv6-http-01)
    fi
    if scenario_selected ip-tls-alpn-01; then
      ip_scenarios+=(ipv4-tls-alpn-01 ipv6-tls-alpn-01)
    fi
    export ACMEX_LE_STAGING_IP_SCENARIOS="$(IFS=,; echo "${ip_scenarios[*]}")"
  fi
  run_cargo_gate le-staging-ip \
    cargo test --test le_staging_ip -- --ignored --nocapture
fi

if scenario_selected eab-ca; then
  run_cargo_gate le-staging-eab \
    cargo test --test le_staging_eab -- --ignored --nocapture
fi

if [[ -x "$SCRIPT_DIR/secret_scan.sh" ]]; then
  "$SCRIPT_DIR/secret_scan.sh"
fi

echo "== LE staging gate completed; directory-only or preflight-only output is not a release pass until full issuance evidence is attached"
echo "== artifacts: $ACMEX_LE_STAGING_ARTIFACT_DIR"
