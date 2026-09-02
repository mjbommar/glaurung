# CFG discovery determinism: diagnosis (2026-09-02)

> **Kind:** design · **Status:** proposed

`docs/development/identity-measurement.md` attributes the structural (L1)
identity scheme's run-to-run AUC spread to `analysis::cfg`'s per-function
wall-clock budget. This document confirms the mechanism, reproduces it, and
lays out fix options. **No `src/` change is made here.**

## 1. Where the wall clock lives

Four budgets exist (`src/analysis/cfg/budgets.rs:14-35`, `Budgets`):
`max_functions`, `max_blocks`, `max_instructions` are pure step counts -
deterministic. `timeout_ms` and `total_timeout_ms` are wall clock.

- **`timeout_ms`** (default `100`, `budgets.rs:46`): a *per-function* clock,
  restarted at every seed in `discover_function`
  (`src/analysis/cfg/walk.rs:112`, `let t0 = std::time::Instant::now();`).
  Checked at `walk.rs:166` (block-dequeue loop) and `walk.rs:212`
  (instruction-decode loop): `if t0.elapsed().as_millis() as u64 >
  budgets.timeout_ms { stats.hit_timeout = true; break; }`. Tripping it
  **truncates that one function's block walk** at whatever block/edge count
  it had reached and sets `FunctionFlags::CFG_WALK_TIMEOUT`
  (`src/core/function.rs:80`, folded into `CFG_INCOMPLETE` at line 91). The
  budget doc comment itself calls this out: "despite the bare name this has
  never bounded an analysis... a binary with 20 000 functions can spend
  20 000 times this and still be inside budget" (`budgets.rs:20-23`).
- **`total_timeout_ms`** (default `0` = no ceiling, `budgets.rs:35,47`): a
  *whole-run* `Deadline` (`budgets.rs:56-116`), checked at `walk.rs:173,216`,
  `worklist.rs:191`, and every `scan_within` seed scan (`budgets.rs:127-136`,
  `seeds.rs` - a dozen call sites). Tripping it sets
  `FunctionFlags::CFG_ANALYSIS_DEADLINE` and can also empty out whole-binary
  seed scans (vtables, jump tables, eh_frame) via `scan_within`. Default is
  unbounded, so it is inert unless a caller opts in (the CLI passes 600000ms;
  `src/python_bindings/analysis.rs:643`).

`src/timeout.rs` is unrelated - a generic tokio async-timeout helper used
elsewhere, not threaded through `analysis::cfg` at all.

Every Python entry point keeps `timeout_ms` nonzero by default and
`total_timeout_ms=0`: `analyze_functions_bytes`/`_path`(`_with_stats`)
(`python_bindings/analysis.rs:273,301,333,365`, `timeout_ms=100`),
`decompile_function`/`sweep` in `ir.rs` (`timeout_ms=5000..10000`). The
identity harness itself, `tests/identity_retrieval/corpus.rs:592`, calls
`analyze_functions_bytes_with_seeds(&data, &Budgets::default(), &seeds)` -
i.e. the 100ms per-function clock, unbounded run.

## 2. Reproduction

Built release (`uv run maturin develop --release`, worktree-local). Ran
`glaurung.analysis.analyze_functions_path_with_stats` (same API the identity
lane uses under the hood) 10x per binary, hashing each function's sorted
`(entry, block_count, edge_count)` tuple set.

**Quiet machine**, 3 in-house fixtures + 2 Cisco Talos MIPS64 binaries:

| Binary | funcs | CFG_INCOMPLETE | digests over 10 runs |
|---|---|---|---|
| `219_rust_iterator_chains-rustc-O0.so` | 692 | 0 | 1/10 (stable) |
| `169_rust_slices_bounds-rustc-O0.so` | 609 | 0 | 1/10 |
| `167_rust_trait_objects-rustc-O0.so` | 579 | 0 | 1/10 |
| `unrar/mips64-clang-3.5-O0_unrar` (1.2MB) | 795 | 4 | 1/10 |
| `curl/mips64-clang-3.5-O0_curl` (2.2MB) | 1126 | **1044** | 1/10 |

Even with 1044/1126 functions timeout-truncated, a quiet machine reproduces
bit-identically - the walk order (`VecDeque` BFS) is deterministic; only the
*moment* the clock fires varies.

**Loaded machine**: started 20 `yes >/dev/null &` busy-loops (24 cores,
load average 5->24) and re-ran the curl binary 6x under `nice -n 19`:

```
run=0 digest=c4686e... elapsed_ms=98693
run=1 digest=92e2db... elapsed_ms=68913
...
TOTAL unique_digests=6/6   (every run differed)
```

run0 vs run1..5 disagreed on 129-260 functions each time. Example, entry
`0x64810`: run0 = `(148 blocks, 178 edges)` [`hit_timeout`], run1 =
`(2048 blocks, 2627 edges)` [`hit max_blocks`, confirmed via
`cfg_incomplete_budgets()` on the quiet-machine run: `['max_blocks']`]. Same
bytes, same deterministic 2048-block cap - CPU contention alone decided
whether that function stopped at 148 blocks or the full 2048. This is the
mechanism `identity-measurement.md` describes, reproduced directly.

## 3. Options

**(a) Replace wall-clock with step counts.** Touches
`src/analysis/cfg/{budgets.rs,walk.rs,worklist.rs,stats.rs}`, `cfg.rs`
(~15 test sites reference `timeout_ms`), `src/core/function.rs` (flag
naming), and every Python signature exposing `timeout_ms`
(`python_bindings/{analysis.rs,ir.rs,exec.rs}`, 8+ `#[pyo3(signature)]`
lines) plus CLI flags (`decompile.py --timeout-ms`, `cfg.py`, `view.py`,
etc). `tools/dectest.py` -> `diff_decompile.py:decompiled_c` shells out to
`glaurung decompile --vas`, which threads a per-function `timeout_ms`
through the identical `walk.rs` clock - so this also touches the fixture
gate. Needs a new deterministic proxy for whatever `timeout_ms` guards
beyond `max_instructions` (e.g. per-block dispatch/table-scan cost). All
four `tests/decompiler_fixtures/*baseline.json` plus `arch_baseline.json`
would need re-verification since truncation points would shift. Estimated
150-300 LOC, wide surface, real risk of moving decompiler fixture cells.

**(b) Give the harness an effectively-unbounded per-function clock.**
`timeout_ms=0` does **not** mean unbounded (unlike `total_timeout_ms`) -
`walk.rs:166`'s check is `elapsed > timeout_ms`, so `0` fires on the first
nonzero tick. But a large sentinel (`u64::MAX`, or a stated ceiling like
3_600_000ms) works: `max_blocks`/`max_instructions` still bound worst-case
work deterministically, so nothing runs away. One-line change to
`tests/identity_retrieval/corpus.rs:592` - build a custom `Budgets` instead
of `Budgets::default()`. Zero `src/` change, no baseline movement, no effect
on any other caller. `CISCO_STRUCTURAL_NOISY_TASKS` in
`tests/identity_retrieval/main.rs` could then be revisited (its noise floor
was set *because of* this jitter) but doesn't need to be, immediately.

**(c) Make the truncated result itself deterministic.** Block-visitation
order is already deterministic (BFS `VecDeque`); the only nondeterminism is
*when* the clock stops it. This collapses into (a) - there's no way to keep
a wall-clock stopping rule and make its firing point reproducible without
also giving it a deterministic proxy.

## Recommendation

**(b)**: ~5 LOC in `tests/identity_retrieval/corpus.rs`, outside `src/`
entirely, fixes exactly the identity harness's reproducibility bug with no
blast radius on the decompiler, CLI, or fixture baselines. (a) is the correct
long-term fix for production callers (the CLI's own default `timeout_ms=100`
is exposed to the same load-dependent jitter) but is a separate, much larger
change that should not ride on this diagnosis.
