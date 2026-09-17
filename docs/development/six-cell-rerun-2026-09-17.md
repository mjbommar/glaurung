# Six-cell rerun at the 2026-09-16 Axeyum pin — sizing and preflight

> **Kind:** working note · **Status:** preflight, written before any timing row
> was observed. The result, when it exists, is in
> `bench-results/glaurung-six-cell-neutral-20260917/` and in
> [`solver-033`](../decisions/solver-033-six-cell-rerun-at-the-2026-09-16-pin.md).

This is item 3 of [`improvement-list-2026-09-16.md`](improvement-list-2026-09-16.md)
(Axeyum's list, item 14): re-run Axeyum ADR-0272's preregistered campaign so
[`solver-002`](../decisions/solver-002-axeyum-as-default-backend.md) gets a
number measured at a pin newer than 2026-07-20. The protocol is frozen in
Axeyum's `docs/research/09-decisions/adr-0272-preregister-six-cell-neutral-warm-regime.md`
and executed by its `scripts/run-glaurung-six-cell-neutral.py`
(SHA-256 `daeec160c41862e3a70cc216831971a402d8b7392e3e6b60504b2503e89fbc7c`).
The runner refuses any revision, executable, driver, CPU, or output root
other than the registered ones, by design; this note states which of those
pins a rerun at head *must* change and which it must not.

## Pins that change (and why)

| Pin | July (ADR-0272) | This rerun | Why |
|---|---|---|---|
| `GLAURUNG_REVISION` | `2961d7c1bca03f14b77b12fb852d193413207982` | `11b68faffc8475115d8eadc2b233bd1a731e3862` (master after [`solver-032`](../decisions/solver-032-axeyum-pin-bump-and-shadow-corpus-prune.md)) | the point of the rerun is the producer at head |
| Axeyum crates | `a9abc6cdc…` (`axeyum-solver` tree `ec3a38f3…`) | `8df853252cdf49c9a27ba71c6ce62fdd1c485dfc` (Cargo.lock, `default-features = false, features = ["qfbv"]`) | the pin bump solver-032 landed |
| `EXECUTABLE_SHA256` | `5d454daf6c12c1d69bc0e28e12c391286b53d1a7735514043b85ea82057ef17b` | recorded in `registration.json` after the build; the runner is copied with this one constant edited | a new source revision is a new binary |
| Features | `solver-z3,solver-axeyum,solver-bitwuzla` | `solver-z3,solver-axeyum` | see "Bitwuzla" below |
| Trace schema | `glaurung-ordered-check-measurement-v3` (six cells) | `…-v2` (four cells) | consequence of the feature set; `src/symbolic/ordered_trace.rs:57` selects v2 when exactly the four Z3/Axeyum cells are present |
| Producer validator | `docs/axeyum-integration/capture/validate_ordered_trace.py` | `tools/axeyum/validate_ordered_trace.py` (SHA-256 `81fcfb73fd7efa83256a5f45b0d2721697fe525a09c7cc9076ccdbc5f0ec28ed`) | the file moved; the copied runner's path is updated |
| Analyzer | Axeyum `5d74283b8` (SHA-256 `ff2131bf…`) | Axeyum `dafe6cd6e`, `scripts/analyze-glaurung-paired-traces.py` SHA-256 `d9431ad02710f161a077f0fbbc1cbaf4d6c777a52831808a5b5df9b8773150c6` | v4 support was added additively since July. Control run before the campaign: the head analyzer over July's five raw `01-dptf-r*` traces reproduces `bench-results/glaurung-six-cell-neutral-20260719/dptf/report.json` byte-for-byte (`f89f28b9…`), so the v2/v3 paths are unchanged |
| Toolchain / kernel | `rustc 1.97.0-nightly (f53b654a8 2026-04-30)`, Linux `7.0.0-27-generic` | `rustc 1.99.0-nightly (be8e82435 2026-07-11)`, Linux `7.0.0-31-generic` | host drift, recorded not chosen |
| Bitwuzla runtime hashes | four `libbitwuzla*.so` SHA-256s | none | no Bitwuzla cell |

## Pins that do NOT change

- The four drivers, in the same order, by SHA-256 — verified present and
  identical in the worktree at `11b68faf`:
  `074be1b9…` DptfDevGen, `13c3b69a…` vwififlt, `f7c8e4f1…` IntcSST,
  `3c062dc5…` SurfacePen.
- The fixed environment, exactly: `GLAURUNG_FAIR_SHADOW=1`,
  `GLAURUNG_CHECK_TIMEOUT_MS=250`, `GLAURUNG_AXEYUM_REPLAY_SAT_CACHE=1`,
  `GLAURUNG_AXEYUM_WARM_MAX_LIVE_PATHS=9`,
  `GLAURUNG_AXEYUM_WARM_MAX_ASSERTIONS_PER_PATH=512`,
  `IOCTLANCE_DEADLINE_SECS=600`, `IOCTLANCE_MAX_ANALYZED_FUNCTIONS=100000`,
  `IOCTLANCE_SOLVE_BUDGET=20000`, `IOCTLANCE_SOLVE_SECS=60`; every
  `GLAURUNG_*`/`IOCTLANCE_*`/`BITWUZLA_*` and `LD_LIBRARY_PATH` inherited from
  the shell is stripped by the runner.
- Logical CPU 2, one worker, `mem-run.sh taskset -c 2`, 64 GiB cap.
- Five repetitions per driver, driver-major, fresh process each, one trace per
  process, the producer validator run on every trace, fail-closed on any
  non-zero exit or validator rejection.
- The analysis: per-occurrence paired ratios collapsed by geometric mean
  across repetitions, geometric mean across occurrences, 10,000-sample
  bootstrap at seed 0, nearest-rank quantiles, per-process CV; only occurrences
  decided by both named cells in every repetition. Ratios are
  `numerator_nanos/denominator_nanos`; greater than one favours the denominator.
- Z3: Ubuntu `libz3-4` 4.13.3-1build1, `libz3.so.4` SHA-256
  `eff8f0f91482d0809aae7aa0ed54cb52ff5ee9b5fe1ed1d2bfa9153c4a2fcfaf` — the same
  bytes as July.

## Bitwuzla: not buildable within the hour, so this is a four-cell rerun

`solver-bitwuzla` is `["symbolic"]` in `Cargo.toml` because
`src/symbolic/solver/bitwuzla_backend.rs` links `libbitwuzla` by hand
(`#[link(name = "bitwuzla")]`), `build.rs` requires `BITWUZLA_LIB_DIR` to
contain `libbitwuzla.so`, and `NativeSession::new` rejects any
`bitwuzla_version()` other than exactly `0.9.1`. What July had was a
prebuilt 0.9.1 under `/home/mjbommar/.cache/codex/bitwuzla-0.9.1/`; that
directory no longer exists on s4. Building it now would need:

- the 0.9.1 tag (the only local source is `axeyum/references/bitwuzla`, a
  shallow graft at `0.9.1-dev`, whose `bitwuzla_version()` the backend would
  reject; the tag is fetchable);
- `meson` and `ninja` (absent; no `pip`, only `uv`);
- GMP development headers (`libgmp-dev` is not installed, `gmp.h` is absent, and
  there is no `sudo`), so GMP itself would have to be built from source first;
- CaDiCaL and SymFPU via meson wraps (network fetch at build time).

That is more than an hour of unmeasured toolchain work whose product would in
any case carry different library hashes from ADR-0272's. Per the brief, the
rerun is therefore **four cells**: `{Z3, Axeyum} × {cold, warm}`. The column
`solver-002` reads is warm Z3/Axeyum (with cold Z3/Axeyum beside it); the
July `Axeyum/Bitwuzla` column has no counterpart here and is not re-measured.

## Preflight finding: the producer at master could not publish a valid trace

The first smoke run (one DptfDevGen process at `11b68faf`, outside the
campaign, before registration) exited 0 and published a v2 trace, and
`tools/axeyum/validate_ordered_trace.py` rejected it:
`per-backend timing exceeds total timing for check-0`. The cause is
`replace_axeyum_timing` in `src/symbolic/solver/mod.rs`, added by the engine
constraint cache (`2c999b67`, 2026-07-20 — one day after the July campaign):
with the cache policy `Off` it still overwrote the legacy `axeyum_nanos` alias
with the wrapper time (the whole four-cell rotation) while `z3_nanos` stayed
the cold-Z3 cell, so `z3_nanos + axeyum_nanos > total_nanos` on every
fair-shadow check. The four measured cell fields
(`z3_cold_nanos`, `z3_warm_nanos`, `axeyum_cold_nanos`, `axeyum_warm_nanos`)
were correct; only the compatibility aliases were wrong. This means **no
`solver-z3,solver-axeyum` fair-shadow trace produced since 2026-07-20 could
have passed the producer validator**, which is consistent with nobody having
run the campaign since.

Fixed on this branch (`b1f420ab`): the aliases `solve()` set survive the
wrapper whenever Z3 was timed; a unit test
(`fair_shadow_aliases_survive_the_engine_cache_wrapper`, needs
`--features solver-z3,solver-axeyum`) pins the validator's invariant on a real
fair-shadow solve and fails on the old code. ADR-0272 allows exactly this
class of repair without a new preregistration ("a pure runner/schema defect
that occurs before a timing row is observed"); the registered producer
revision is therefore this branch's head, which differs from master
`11b68faf` by that one fix plus documentation.

## Host

- Host s4, `12th Gen Intel(R) Core(TM) i5-12600K` (the same CPU model as the
  July run's `server0`), 16 logical CPUs, `os.sched_getaffinity(0)` includes 2.
  Logical CPU 2's SMT sibling is CPU 3 (`thread_siblings_list` = `2-3`).
- Load at preflight (00:14–00:17 UTC): 6.5–8.8 one-minute, ~9 fifteen-minute.
  Two other lanes were running test binaries at ~100–210 % CPU each. The
  alternative host s6 (AMD Ryzen 7 7840HS, load 0.4) has **no** `libz3.so`
  (its `/usr/bin/z3` is a static binary), so a `solver-z3` build cannot run
  there without building z3 from source and changing the Z3 identity pin, and
  its CPU differs from July's. The rerun stays on s4, on CPU 2, with the
  one-minute load and the process list recorded at launch and at completion.
  The protocol's own per-process CV gate (≤ 3 % on the primary warm pair) is
  what classifies a noisy run; a gate failure is a result, not a retry.
- The whole July campaign took 10 min 29 s of wall time for 20 processes
  (5.8 s DptfDevGen, 52 s vwififlt, 17.5 s IntcSST, 35 s SurfacePen per
  process), so the rerun is launched when the one-minute load is below 8 and
  left alone until its `DONE` marker appears.

## Steps after this note

1. Build `--release --example ioctlance --features solver-z3,solver-axeyum`
   at `11b68faf` into `/data0/axeyum/scratch/sixcell/target` (cargo serialized,
   `-j2`); record the executable SHA-256 and its full `ldd` resolution.
2. Register `bench-results/glaurung-six-cell-neutral-20260917/registration.json`
   with `zero_result_rows: true` and the table above; commit.
3. Copy the runner, change exactly `GLAURUNG_REVISION`, `EXECUTABLE_SHA256`,
   and the validator path; record its SHA-256; run detached with a `DONE`
   marker; wait on the marker.
4. Analyze with the head analyzer, once per driver, then an independent
   same-input rerun for byte identity; write `README.md`, `result-summary.json`,
   and `solver-033`.
