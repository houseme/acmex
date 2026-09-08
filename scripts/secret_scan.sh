#!/usr/bin/env bash
# High-confidence repository/evidence secret scan for release gates.
#
# This intentionally avoids broad "password=" heuristics because the docs
# contain SecretRef examples. The patterns below target material that should
# never be committed or archived verbatim.
set -euo pipefail

# Prefer ripgrep; fall back to plain grep -rE so the gate also runs on
# runners without rg (same exit semantics: 0 = match found, 1 = none).
if command -v rg >/dev/null 2>&1; then
  scan() {
    rg -n --hidden --no-heading --glob '!.git/**' --glob '!target/**' \
      --regexp "$1" "${scan_paths[@]}"
  }
  scan_evidence() {
    rg -n --hidden --no-heading --regexp "$1" "target/pebble-e2e"
  }
else
  echo "note: ripgrep not found; falling back to grep" >&2
  scan() {
    grep -rnE --exclude-dir=.git --exclude-dir=target \
      --regexp "$1" "${scan_paths[@]}"
  }
  scan_evidence() {
    grep -rnE --regexp "$1" "target/pebble-e2e" 2>/dev/null
  }
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
  if scan "$pattern"; then
    hits=1
  fi
  if [[ -d "target/pebble-e2e" ]] && scan_evidence "$pattern"; then
    hits=1
  fi
done

if [[ "$hits" != "0" ]]; then
  echo "FAIL: high-confidence secret material was found" >&2
  exit 1
fi

echo "secret scan passed"
