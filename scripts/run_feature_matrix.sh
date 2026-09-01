#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo test --test release_gate_docs feature_matrix_lists_every_cargo_feature
cargo check --no-default-features
cargo check --all-features
