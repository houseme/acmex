#!/usr/bin/env bash
# Public-API semver gate (roadmap T21).
#
# Compares the workspace against the last published release. Breaking changes
# that were deliberately accepted for the 0.9.0/0.10.0 line are enumerated in
# docs/roadmap/v0.10.0/semver-waiver-accepted.txt (rationale per item in
# docs/roadmap/v0.10.0/SEMVER_WAIVER.md). The gate fails on any failure that
# is NOT covered by the accepted list; once 0.10.0 is published the baseline
# moves and the accepted list should shrink to empty.
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

waiver_file="docs/roadmap/v0.10.0/semver-waiver-accepted.txt"
output=$(set +e; cargo "${args[@]}" 2>&1; status=$?; printf 'SEMVER_EXIT=%s' "$status")
status=$(printf '%s' "$output" | sed -n 's/^SEMVER_EXIT=//p' | tail -1)
printf '%s\n' "$output" | grep -v '^SEMVER_EXIT=' || true

if [[ "$status" == "0" ]]; then
  echo "semver gate passed with no breaking changes"
  exit 0
fi

if [[ "${ACMEX_SEMVER_WRITE_WAIVER:-}" == "1" ]]; then
  # Deliberate regeneration (see the accepted list header): captures the
  # current failure signatures as the new accepted baseline.
  items=$(printf '%s\n' "$output" | awk '/Failed in:/{capture=1; next} /^$/{capture=0} capture' | sed '/^[[:space:]]*$/d' | sed -E 's/,? (previously )?in (file )?[^ ]+:[0-9]+$//' | sort -u)
  {
    printf '# Accepted public-API breaking changes vs the published acmex 0.8.0.\n'
    printf '# One fixed-string signature per line, matched against every failing item\n'
    printf '# line of cargo-semver-checks. Rationale per item:\n'
    printf '# docs/roadmap/v0.10.0/SEMVER_WAIVER.md.\n'
    printf '# Regenerate deliberately (never blindly):\n'
    printf '#   ACMEX_SEMVER_WRITE_WAIVER=1 scripts/run_semver_check.sh\n'
    printf '\n%s\n' "$items"
  } > "$waiver_file"
  echo "waiver list regenerated with $(printf '%s\n' "$items" | grep -c .) signatures; review the diff before committing" >&2
  exit 0
fi

# Collect the failing item lines ("Failed in:" blocks).
items=$(printf '%s\n' "$output" | awk '/Failed in:/{capture=1; next} /^$/{capture=0} capture' | sed '/^[[:space:]]*$/d')
total=$(printf '%s\n' "$items" | grep -c . || true)

unexpected=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  matched=0
  while IFS= read -r sig; do
    [[ -z "$sig" || "$sig" == \#* ]] && continue
    if printf '%s' "$line" | grep -qF -- "$sig"; then
      matched=1
      break
    fi
  done < "$waiver_file"
  if [[ "$matched" != "1" ]]; then
    echo "UNEXPECTED BREAKING CHANGE (not covered by the waiver list):" >&2
    echo "  $line" >&2
    unexpected=1
  fi
done <<< "$items"

if [[ "$unexpected" != "0" ]]; then
  echo "semver gate FAILED: breaking changes beyond the accepted waiver; update the code or extend docs/roadmap/v0.10.0/semver-waiver-accepted.txt with release-manager sign-off" >&2
  exit 1
fi

echo "semver gate passed: $total failing item(s), all covered by the reviewed waiver (docs/roadmap/v0.10.0/SEMVER_WAIVER.md)"
