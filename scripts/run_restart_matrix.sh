#!/usr/bin/env bash
set -euo pipefail

cargo test --test e2e_restart_matrix -- --nocapture
