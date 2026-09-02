#!/usr/bin/env bash
# High-confidence repository/evidence secret scan for release gates.
#
# This intentionally avoids broad "password=" heuristics because the docs
# contain SecretRef examples. The patterns below target material that should
# never be committed or archived verbatim.
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) is required for scripts/secret_scan.sh" >&2
  exit 1
fi

scan_paths=(
  ".github"
  "Cargo.toml"
  "Cargo.lock"
  "docs"
  "scripts"
  "src"
  "tests"
)

patterns=(
  '-----BEGIN (RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----'
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  'gh[pousr]_[A-Za-z0-9_]{36,}'
  'github_pat_[A-Za-z0-9_]{40,}'
  'xox[baprs]-[A-Za-z0-9-]{20,}'
  'sk_live_[A-Za-z0-9]{20,}'
)

hits=0
for pattern in "${patterns[@]}"; do
  if rg -n --hidden --no-heading --glob '!.git/**' --glob '!target/**' \
    --regexp "$pattern" "${scan_paths[@]}"; then
    hits=1
  fi
  if [[ -d "target/pebble-e2e" ]] &&
    rg -n --hidden --no-heading --regexp "$pattern" "target/pebble-e2e"; then
    hits=1
  fi
done

if [[ "$hits" != "0" ]]; then
  echo "FAIL: high-confidence secret material was found" >&2
  exit 1
fi

echo "secret scan passed"
