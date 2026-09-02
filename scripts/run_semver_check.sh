#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-semver-checks >/dev/null 2>&1; then
  cargo install cargo-semver-checks --locked
fi

args=(semver-checks check-release --package acmex --all-features)

if [[ -n "${ACMEX_SEMVER_BASELINE_REV:-}" ]]; then
  args+=(--baseline-rev "${ACMEX_SEMVER_BASELINE_REV}")
elif [[ -n "${ACMEX_SEMVER_BASELINE_VERSION:-}" ]]; then
  args+=(--baseline-version "${ACMEX_SEMVER_BASELINE_VERSION}")
fi

cargo "${args[@]}"
