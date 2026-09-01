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
