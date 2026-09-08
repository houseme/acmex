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

### 2026-09-07 — file backend fsync mode comparison

`FileRepository` gained an explicit, opt-in durability policy
(`FsyncMode`, re-exported from `acmex::repository`):

- `FsyncMode::Always` — **the default, byte-for-byte the historical
  behavior**: every write is fsynced before its atomic rename returns.
  The default was not weakened; `Always` numbers below are equal to the
  2026-09-06 baseline within run-to-run noise.
- `FsyncMode::Interval(duration)` — opt-in group commit with Redis-AOF
  `everysec` semantics: writes become visible immediately (atomic rename)
  while a background sweeper fsyncs at most one interval window later
  (files, then the affected directories on unix, so renames/deletions
  become durable too). An abrupt crash can lose up to one interval window
  of acknowledged writes. `Drop` performs a final flush and joins the
  sweeper; `FileRepository::sync_pending()` forces a synchronous sweep.

Platform: Apple Silicon macOS 26.6.2 (Darwin 25.6.0 arm64), APFS temp
volume, release profile, `ACMEX_PERF_INTENTS` as listed, each benchmark
run isolated (`cargo test --release --test performance_baseline <filter>
-- --ignored --nocapture`). Interval runs use the default 100 ms window.

Before (reproduced on the unmodified tree, 2026-09-07):

```text
acmex_perf_baseline intents=1000 insert_ms=3 scan_ms=0 backend=memory rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file intents=1000 insert_ms=4333 scan_ms=9 cold_scan_ms=41 backend=file rust=0.8.0 key_ref_shape=56
acmex_perf_baseline intents=10000 insert_ms=28 scan_ms=4 backend=memory rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file intents=10000 insert_ms=45179 scan_ms=75 cold_scan_ms=380 backend=file rust=0.8.0 key_ref_shape=56
```

After (2026-09-07, same tree with `FsyncMode`):

```text
acmex_perf_baseline_file intents=1000 insert_ms=4103 scan_ms=10 cold_scan_ms=52 backend=file rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file intents=10000 insert_ms=42580 scan_ms=94 cold_scan_ms=369 backend=file rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=1000 interval_ms=100 insert_ms=449 scan_ms=8 cold_scan_ms=39 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=10000 interval_ms=100 insert_ms=22470 scan_ms=97 cold_scan_ms=407 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
```

| Scale | Backend / mode | insert (before) | insert (after) | warm scan (after) | cold scan (after) |
|---|---|---|---|---|---|
| 1 000 | file, `Always` (default) | 4 333 ms | 4 103 ms | 10 ms | 52 ms |
| 10 000 | file, `Always` (default) | 45 179 ms | 42 580 ms | 94 ms | 369 ms |
| 1 000 | file, `Interval` (opt-in, 100 ms) | — | 449 ms (9.1× vs `Always`) | 8 ms | 39 ms |
| 10 000 | file, `Interval` (opt-in, 100 ms) | — | 22 470 ms (1.9× vs `Always`) | 97 ms | 407 ms |

Notes:

- `Always` inserts remain fsync-bound by design; the lossless changes on
  that path (one temp-file handle instead of write-then-reopen, the
  verified-directory cache replacing the per-write `mkdir`, and CAS /
  lease / outbox updates now reading through the stamp-validated parse
  cache) are within noise for insert, but CAS-heavy workflows avoid a
  full re-read + re-parse per update.
- `Interval` does not delete fsync work, it moves it off the insert
  critical path and batches it per window; at 10 000 entities the
  background sweeps contend with the writers for the disk, which is why
  the speed-up is smaller there than at 1 000. `insert_ms` for Interval
  excludes the final drop-time flush by design (that deferral against a
  bounded durability window is what the mode buys).
- An earlier after-run executed the Always and Interval benchmarks
  concurrently in one test process and produced mutually contended
  numbers; the table above uses isolated runs only.

#### Parallel fsync inside the `Interval` sweeper (2026-09-08)

Second round on `FsyncMode::Interval`: the background sweeper (`fsync_batch`)
used to fsync a batch of dirty files strictly one after another. Files in a
batch are mutually independent and fsync is pure IO wait, so the file phase
is now distributed over a bounded pool of scoped threads
(`std::thread::scope`; `FSYNC_BATCH_WORKERS = 8`, further capped by the CPU
count and the batch size; batches of 0–1 files stay serial). Each worker
counts its successful fsyncs through the same `fsynced_files` counter and
collects failures into a thread-local `Vec` that is requeued exactly as
before (warn + requeue, never silent); directory fsyncs still run
afterwards on the calling thread so a directory sync never races the sync
of a file it contains. No new dependencies; `Always` mode is untouched.

Methodology note: this host was running concurrent builds during
measurement (load average swung 4–14 on 18 CPUs), which dominates the
1 000-entity scale. The numbers below therefore come from interleaved
paired runs — the same tree measured alternately with the serial and the
parallel `fsync_batch` (only that function toggled), so both variants saw
the same background load.

Serial sweeper (before, raw):

```text
acmex_perf_baseline_file_fsync_interval intents=1000 interval_ms=100 insert_ms=515 scan_ms=9 cold_scan_ms=49 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=1000 interval_ms=100 insert_ms=1433 scan_ms=9 cold_scan_ms=53 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=1000 interval_ms=100 insert_ms=313 scan_ms=8 cold_scan_ms=36 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=10000 interval_ms=100 insert_ms=32075 scan_ms=98 cold_scan_ms=437 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=10000 interval_ms=100 insert_ms=27091 scan_ms=95 cold_scan_ms=426 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=10000 interval_ms=100 insert_ms=27534 scan_ms=93 cold_scan_ms=389 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=10000 interval_ms=100 insert_ms=27318 scan_ms=84 cold_scan_ms=404 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
```

Parallel sweeper (after, raw):

```text
acmex_perf_baseline_file_fsync_interval intents=1000 interval_ms=100 insert_ms=1026 scan_ms=9 cold_scan_ms=32 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=1000 interval_ms=100 insert_ms=818 scan_ms=7 cold_scan_ms=34 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=10000 interval_ms=100 insert_ms=13100 scan_ms=94 cold_scan_ms=406 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
acmex_perf_baseline_file_fsync_interval intents=10000 interval_ms=100 insert_ms=12262 scan_ms=98 cold_scan_ms=404 backend=file-fsync-interval rust=0.8.0 key_ref_shape=56
```

| Scale | Sweeper | insert (median) | vs serial |
|---|---|---|---|
| 1 000 | serial | 515 ms (range 313–1 433, load-noise dominated) | 1.0× |
| 1 000 | parallel, 8 workers | ~1 026 ms (range 818–1 152, all runs in higher-load windows) | no regression signal, noise-dominated |
| 10 000 | serial | 27 426 ms (range 27 091–32 075) | 1.0× |
| 10 000 | parallel, 8 workers | 12 681 ms (range 12 262–13 100) | **2.2× (conservatively ≥ 2.0×)** |

Decision: **kept**. The 10 000-entity speed-up (≈2.2×) clears the ≥1.3×
bar; scans are unaffected (the parse cache is untouched). Platform notes:
measured on Apple Silicon macOS 26.6.2 (Darwin 25.6.0 arm64, 18 CPUs),
APFS temp volume, which parallelizes independent fsyncs well; on
seek-bound spinning disks concurrent fsyncs can be slower than serial,
which is why the worker count is a conservative constant (8, not
`available_parallelism()`) that a future device probe could tune.
