# v0.9.0 Performance Baseline

The baseline is a regression tripwire, not a production throughput claim.

Run:

```bash
scripts/run_performance_baseline.sh
```

The script records:

- AcmeX package version.
- Rust toolchain.
- Host operating system and architecture.
- Intent count.
- In-memory insert and scan elapsed time.

Recommended release sample sizes:

- `ACMEX_PERF_INTENTS=1000`
- `ACMEX_PERF_INTENTS=10000`

Attach the raw script output to the release evidence. A missing baseline is not
a release pass.

## Recorded Runs

### 2026-09-06 — post-L4-closeout baseline (Apple Silicon macOS, OrbStack host, release profile with thin LTO)

| Scale | Backend | insert | warm scan | cold scan |
|---|---|---|---|---|
| 1 000 | memory | 3 ms | <1 ms | — |
| 10 000 | memory | 42 ms | 10 ms | — |
| 1 000 | file | 4 089 ms (fsync-bound) | 11 ms | 45 ms |
| 10 000 | file | 40 544 ms (fsync-bound) | 120 ms | 508 ms |

Notes:

- File-backend insert time is dominated by per-entity fsync; the warm-scan
  column reflects the stat-validated parse cache (cold scan pays one
  stat+read per entity).
- Numbers captured with `cargo test --release --test performance_baseline --
  --ignored --nocapture` on the merged main line (76+ commits past the
  v0.10.0 evidence baseline).
