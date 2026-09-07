#!/usr/bin/env bash
# L5 release gate (roadmap T20): live infrastructure and HA evidence entrypoint.
#
#   RUN_LIVE_INFRA=1 scripts/run_live_infra.sh
#
# This script is deliberately environment-gated. Missing infrastructure is a
# skip (exit 77) before RUN_LIVE_INFRA is set, and a failure after it is set.
set -euo pipefail

if [[ "${RUN_LIVE_INFRA:-}" != "1" ]]; then
  echo "SKIP: RUN_LIVE_INFRA=1 is required. A skipped live infra run is not a release pass." >&2
  exit 77
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "FAIL: cargo is required for scripts/run_live_infra.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
export ACMEX_LIVE_INFRA_ARTIFACT_DIR="${ACMEX_LIVE_INFRA_ARTIFACT_DIR:-$REPO_DIR/target/live-infra/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$ACMEX_LIVE_INFRA_ARTIFACT_DIR"

{
  printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'git_sha=%s\n' "$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
  printf 'scenarios=%s\n' "${ACMEX_LIVE_INFRA_SCENARIOS:-all}"
} >"$ACMEX_LIVE_INFRA_ARTIFACT_DIR/environment.txt"

run_cargo_gate() {
  local name="$1"
  shift
  echo "== running $name"
  if ! "$@" 2>&1 | tee "$ACMEX_LIVE_INFRA_ARTIFACT_DIR/${name}.log"; then
    echo "== $name FAILED; artifacts: $ACMEX_LIVE_INFRA_ARTIFACT_DIR" >&2
    exit 1
  fi
}

scenario_selected() {
  local needle="$1"
  local raw="${ACMEX_LIVE_INFRA_SCENARIOS:-all}"
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

run_cargo_gate live-infra-preflight \
  cargo test --test live_infra_evidence -- --ignored --nocapture

if scenario_selected reference-http-agent; then
  run_cargo_gate reference-http-agent \
    cargo test --test agent_live -- --nocapture
fi

if scenario_selected redis; then
  export ACMEX_TEST_REDIS_URL="${ACMEX_LIVE_REDIS_URL:?missing ACMEX_LIVE_REDIS_URL}"
  run_cargo_gate redis-repository-contract \
    cargo test --features redis --test repository_redis_contract -- --ignored --nocapture
fi

if scenario_selected sink-http-agent; then
  run_cargo_gate sink-http-agent \
    cargo test --test http_agent_sink_live -- --ignored --nocapture
fi

if [[ "${RUN_LIVE_DNS_CLOUDFLARE:-}" == "1" ]]; then
  export ACMEX_LIVE_DNS_TYPE=cloudflare
  export ACMEX_LIVE_DNS_ZONE="${ACMEX_LIVE_DNS_CLOUDFLARE_ZONE:?missing ACMEX_LIVE_DNS_CLOUDFLARE_ZONE}"
  export ACMEX_LIVE_DNS_TOKEN="${ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN:?missing ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN}"
  run_cargo_gate live-dns-cloudflare \
    cargo test --features dns-cloudflare --test dns_provider_live -- --ignored --nocapture
fi

if [[ "${RUN_LIVE_DNS_ROUTE53:-}" == "1" ]]; then
  export ACMEX_LIVE_DNS_TYPE=route53
  export ACMEX_LIVE_DNS_ZONE="${ACMEX_LIVE_DNS_ROUTE53_ZONE:?missing ACMEX_LIVE_DNS_ROUTE53_ZONE}"
  export ACMEX_LIVE_DNS_EXTRA_hosted_zone_id="${ACMEX_LIVE_DNS_ROUTE53_HOSTED_ZONE_ID:?missing ACMEX_LIVE_DNS_ROUTE53_HOSTED_ZONE_ID}"
  unset ACMEX_LIVE_DNS_TOKEN
  run_cargo_gate live-dns-route53 \
    cargo test --features dns-route53 --test dns_provider_live -- --ignored --nocapture
fi

if [[ -x "$SCRIPT_DIR/secret_scan.sh" ]]; then
  "$SCRIPT_DIR/secret_scan.sh"
fi

echo "== live infra gate completed"
echo "== artifacts: $ACMEX_LIVE_INFRA_ARTIFACT_DIR"
