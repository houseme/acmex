#!/usr/bin/env bash
# L5 release gate (roadmap T20): live infrastructure and HA evidence entrypoint.
#
#   RUN_LIVE_INFRA=1 scripts/run_live_infra.sh
#
# This script is deliberately environment-gated. Missing infrastructure assets
# are an explicit skip (exit 77), never a successful live-evidence run.
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

skip_missing_assets() {
  local scenario="$1"
  shift
  echo "SKIP: $scenario requires live assets: $*. No live evidence was collected; a skip is not a release pass." >&2
  exit 77
}

require_nonempty_env() {
  local scenario="$1"
  shift
  local name
  for name in "$@"; do
    if [[ -z "${!name:-}" ]]; then
      skip_missing_assets "$scenario" "$@"
    fi
  done
}

require_secret_ref() {
  local scenario="$1"
  local name="$2"
  case "${!name}" in
    env:*|file:*) ;;
    *)
      echo "FAIL: $scenario requires $name to be an env:/file: SecretRef; literal credentials are not accepted." >&2
      exit 1
      ;;
  esac
}

require_readable_file() {
  local scenario="$1"
  local name="$2"
  if [[ ! -r "${!name}" ]]; then
    skip_missing_assets "$scenario" "$name (readable file)"
  fi
}

scan_live_artifacts() {
  local pattern
  local patterns=(
    '-----BEGIN (RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----'
    'AKIA[0-9A-Z]{16}'
    'ASIA[0-9A-Z]{16}'
    'gh[pousr]_[A-Za-z0-9_]{36,}'
    'github_pat_[A-Za-z0-9_]{40,}'
    'xox[baprs]-[A-Za-z0-9-]{20,}'
    'sk_live_[A-Za-z0-9]{20,}'
  )

  for pattern in "${patterns[@]}"; do
    if command -v rg >/dev/null 2>&1; then
      if rg -q --hidden --no-messages --regexp "$pattern" "$ACMEX_LIVE_INFRA_ARTIFACT_DIR"; then
        echo "FAIL: refusing to retain live-infra artifacts that match a high-confidence secret pattern" >&2
        exit 1
      fi
    elif grep -rqE "$pattern" "$ACMEX_LIVE_INFRA_ARTIFACT_DIR"; then
      echo "FAIL: refusing to retain live-infra artifacts that match a high-confidence secret pattern" >&2
      exit 1
    fi
  done
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

if scenario_selected sink-kubernetes; then
  require_nonempty_env sink-kubernetes \
    ACMEX_LIVE_KUBECONFIG ACMEX_LIVE_K8S_ENDPOINT ACMEX_LIVE_K8S_TOKEN \
    ACMEX_LIVE_K8S_CA ACMEX_LIVE_K8S_NAMESPACE
  require_readable_file sink-kubernetes ACMEX_LIVE_KUBECONFIG
  require_readable_file sink-kubernetes ACMEX_LIVE_K8S_CA
  require_secret_ref sink-kubernetes ACMEX_LIVE_K8S_TOKEN
  if ! command -v kubectl >/dev/null 2>&1; then
    skip_missing_assets sink-kubernetes kubectl
  fi
  # The live test's independent cross-check deliberately uses kubectl; point
  # it at the same controlled cluster without recording the kubeconfig.
  export KUBECONFIG="$ACMEX_LIVE_KUBECONFIG"
fi

if scenario_selected sink-vault; then
  require_nonempty_env sink-vault ACMEX_LIVE_VAULT_ADDR ACMEX_LIVE_VAULT_TOKEN_REF
  require_secret_ref sink-vault ACMEX_LIVE_VAULT_TOKEN_REF
  # Keep the public gate variables as SecretRefs and adapt them only for the
  # existing test's intentionally explicit configuration names.
  export ACMEX_LIVE_VAULT_ENDPOINT="$ACMEX_LIVE_VAULT_ADDR"
  export ACMEX_LIVE_VAULT_TOKEN="$ACMEX_LIVE_VAULT_TOKEN_REF"
fi

if scenario_selected dual-process-fencing; then
  require_nonempty_env dual-process-fencing \
    ACMEX_LIVE_FENCING_REPOSITORY ACMEX_LIVE_FENCING_WORKERS
  if [[ "$ACMEX_LIVE_FENCING_WORKERS" != "2" ]]; then
    echo "FAIL: dual-process-fencing requires ACMEX_LIVE_FENCING_WORKERS=2" >&2
    exit 1
  fi
  case "$ACMEX_LIVE_FENCING_REPOSITORY" in
    redis://*|rediss://*) ;;
    *)
      echo "FAIL: dual-process-fencing currently supports a shared Redis repository URL" >&2
      exit 1
      ;;
  esac
  export ACMEX_TEST_REDIS_URL="$ACMEX_LIVE_FENCING_REPOSITORY"
fi

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

if scenario_selected sink-kubernetes; then
  run_cargo_gate sink-kubernetes \
    cargo test --test k8s_sink_live -- --ignored --nocapture
fi

if scenario_selected sink-vault; then
  run_cargo_gate sink-vault \
    cargo test --test vault_sink_live -- --ignored --nocapture
fi

if scenario_selected dual-process-fencing; then
  run_cargo_gate dual-process-fencing \
    cargo test --features redis --test dual_instance_fencing_live -- --ignored --nocapture
fi

if scenario_selected dns-cloudflare && [[ "${RUN_LIVE_DNS_CLOUDFLARE:-}" == "1" ]]; then
  export ACMEX_LIVE_DNS_TYPE=cloudflare
  export ACMEX_LIVE_DNS_ZONE="${ACMEX_LIVE_DNS_CLOUDFLARE_ZONE:?missing ACMEX_LIVE_DNS_CLOUDFLARE_ZONE}"
  export ACMEX_LIVE_DNS_TOKEN="${ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN:?missing ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN}"
  run_cargo_gate live-dns-cloudflare \
    cargo test --features dns-cloudflare --test dns_provider_live -- --ignored --nocapture
fi

if scenario_selected dns-route53 && [[ "${RUN_LIVE_DNS_ROUTE53:-}" == "1" ]]; then
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
scan_live_artifacts

echo "== live infra gate completed"
echo "== artifacts: $ACMEX_LIVE_INFRA_ARTIFACT_DIR"
