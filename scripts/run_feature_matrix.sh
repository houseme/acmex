#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo test --test release_gate_docs feature_matrix_lists_every_cargo_feature
# `-D warnings` under both feature extremes: `cargo check` alone let a
# no-default-features-only unused-variable warning slip through the gate
# twice (chain.rs fallback, jws.rs test helper).
cargo clippy --no-default-features --all-targets -- -D warnings
cargo check --no-default-features
cargo check --all-features
cargo clippy --all-features --all-targets -- -D warnings
