#!/usr/bin/env bash
set -euo pipefail

echo "acmex_perf_host os=$(uname -s) arch=$(uname -m) rust=$(rustc --version)"
cargo test --test performance_baseline -- --ignored --nocapture
