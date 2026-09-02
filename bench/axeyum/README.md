# axeyum vs z3: a bottom-up benchmark for glaurung's QF_BV workload

> **Snapshot status:** the checked-in result files are immutable historical
> evidence from Glaurung `9ace064` on 2026-07-17, not current performance
> claims. That revision predates the wide-constant Z3 adapter fix in `4ae96cf`.
> The current harness grades both backends at every width and exits nonzero on
> any wrong verdict; rerunning the script replaces the result files and stamps
> the current revisions in `provenance.txt`.

> A reproducible, layered benchmark comparing the **axeyum** (pure-Rust,
> in-process) and **z3** (libz3 via the `z3` crate) backends on the exact
> solver workload glaurung's symbolic-execution engine produces. Built to be a
> load-bearing artifact for the axeyum/glaurung publication: every number here
> is regenerable from a clean checkout with one script.

## Thesis under test

Symbolic execution of binaries issues **very many small, mostly-independent
QF_BV queries**, then (via the warm/incremental path) **many related queries
that share long assertion prefixes**. The claims:

- **C1 Correctness:** axeyum returns the same verdicts as z3 (and as
  construction-truth) on glaurung's query distribution.
- **C2 Cold speed:** on small one-shot formulas axeyum beats z3 because it has
  no per-call FFI/context floor; the edge shrinks as formulas grow.
- **C3 Warm speed:** retained incremental state (axeyum's warm path) is the
  structural lever that turns glaurung's real driver streams into a net win.
- **C4 Deployability/robustness:** pure Rust, no libz3, wide-width correctness,
  DRAT proofs, zero crashes/hangs at scale.

## Design: bottom-up tiers

The benchmark is deliberately layered from solver fundamentals up to the real
application, so a reader can see *where* any aggregate number comes from.

| Tier | What | Harness | Isolates |
|---|---|---|---|
| 0 | **Solver primitives** -- every QF_BV operator x width, sat+unsat | `examples/axeyum_bench_primitives.rs` | per-operator blast cost + verdict correctness |
| 1 | **Formula families** -- 20 path-condition-shaped formulas | `examples/axeyum_diff.rs` | realistic small-formula shapes |
| 1b | **Mechanism sweep** -- always-sat family across width x conjunct count | `examples/axeyum_sweep.rs` | the fixed-overhead floor vs bit-blast growth |
| 2 | **Warm vs one-shot** -- a narrowing path condition re-checked per step | `examples/axeyum_incremental.rs` | the incremental-reuse lever (C3) |
| 3 | **Real driver streams** -- full ioctlance analysis, shadow-diff | `examples/ioctlance.rs` | the production query distribution |

### Method (shared discipline)

- **Shadow-differential (Tiers 1, 3):** `GLAURUNG_SHADOW_DIFF=1` runs *both*
  backends on every query, with z3 authoritative so the query stream and path
  lineage are identical across runs. The two per-backend times are therefore
  apples-to-apples on the same work.
- **Construction-truth grading (Tier 0):** each case's verdict is known *by
  construction* (a SAT case has an explicit witness; an UNSAT case is
  `t == v AND t == v^1`). Both backends are graded against that truth -- no
  solver is trusted as the oracle -- so a wrong verdict from *either* side is
  caught, not merely "they disagree." A concrete evaluator mirroring the IR
  semantics computes the reachable SAT target.
- **One-shot pattern:** Tiers 0/1/1b build a fresh solver per `check`, matching
  glaurung's current non-incremental `Solver` trait. Tier 2 additionally
  exercises the warm path. Timing is median of N reps.
- **Instrument unknown/error per backend, always.** A "faster" number that
  coincides with dropped work (fast-failure) is invalid; Tier 3 reports
  `unknown-split` counts, not just verdict agreement. (This lesson was learned
  the hard way -- see Findings.)

## How to reproduce

From a clean checkout with both backends buildable:

```sh
# one shot, fast drivers only (~few minutes):
bench/axeyum/run_benchmark.sh --fast

# include the large kernel drivers tcpip/dxgkrnl (minutes each):
bench/axeyum/run_benchmark.sh --full-drivers
```

Outputs land in `bench/axeyum/results/` (JSONL for Tier 0, tables for the rest) with a
`provenance.txt` stamp (git revs, host, CPU, rustc). If the glaurung tree fails
to build against the local axeyum checkout, sync axeyum
(`git -C ~/projects/personal/axeyum pull --ff-only`) -- glaurung HEAD tracks a
recent axeyum revision.

## Historical results (the checked-in run)

Provenance: glaurung `9ace064`, axeyum `1cc1918`, i9-12900K, rustc 1.97-nightly,
2026-07-17. See `bench/axeyum/results/provenance.txt`.

### Tier 0 -- primitives (230 cells, all operators x {8,16,32,64,128}b, sat+unsat)

- **Correctness: axeyum 230/230 correct. z3 229/230.** The single z3 miss is a
  128-bit `concat` that is genuinely SAT: glaurung's z3 adapter truncates the
  wide constant (`z3_backend.rs:122`, `value as u64`) and returns a wrong
  UNSAT; axeyum handles the full u128 and is correct. See Findings.
- **Head-to-head speed (<=64b, both sound): median 12.0x, axeyum 3.53x faster
  by median-sum.** By width the edge tracks the fixed-floor prediction exactly:

  | width | median speedup (z3/axeyum) |
  |---|---|
  | 8b | 18.5x |
  | 16b | 14.7x |
  | 32b | 10.3x |
  | 64b | 7.0x |

  By operator class (<=64b): bitwise 20.0x, shift 15.2x, struct 12.6x,
  compare 10.7x, unary 10.5x, **arith 5.1x** (mul/udiv are the costliest to
  bit-blast -- the narrowest axeyum margin, as expected).

### Tier 1 -- formula families (20 cases)

0 confident disagreements. z3 1002.9 ms vs axeyum 75.7 ms total -> **axeyum
~13x faster** on these small path-condition shapes.

### Tier 1b -- mechanism sweep (why C2 holds)

Per-solve us, z3/axeyum (speedup), always-sat family, K conjuncts x width:

| width\K | K=1 | K=4 | K=16 | K=64 |
|---|---|---|---|---|
| 8b | 474/15 (31.7x) | 997/47 (21.0x) | 2869/191 (15.0x) | 10372/774 (13.4x) |
| 16b | 359/28 (13.1x) | 549/103 (5.3x) | 1225/400 (3.1x) | 3887/1653 (2.4x) |
| 32b | 463/56 (8.3x) | 916/215 (4.3x) | 2636/874 (3.0x) | 9607/3610 (2.7x) |
| 64b | 841/128 (6.6x) | 2165/677 (3.2x) | 7682/2103 (3.7x) | 29170/9549 (3.1x) |

The K=1 column is the decisive floor: a trivial query costs z3 **359-841 us**
(FFI + context + marshalling, paid every call) but axeyum **15-128 us**. axeyum's
cost then grows with real bit-blast work while z3's floor stays flat, so the two
converge as formulas grow -- but axeyum stays ahead across the whole sweep.

### Tier 2 -- warm vs one-shot (why C3 is the lever)

Narrowing 32-bit path condition, explored to depth K=24 (200 reps):

| | ms/run | vs z3 |
|---|---|---|
| z3 one-shot (current backend) | 13.86 | 1.0x |
| axeyum one-shot | 1.49 | 0.11x (9x faster) |
| **axeyum WARM (incremental)** | **0.195** | **0.014x (71x faster; 7.6x over axeyum one-shot)** |

Retained incremental state is worth another ~8x beyond axeyum's already-fast
one-shot path -- the structural justification for wiring the warm/direct-delta
path into the explorer.

### Tier 3 -- real driver query streams (shadow-diff, identical stream)

Speedup = z3_ms / axeyum_ms on the same stream; adaptive-default warm.

| driver | queries | disagreements | unknown-splits | speedup |
|---|---|---|---|---|
| vwififlt | 4,753 | 0 | 0 | 3.3x |
| DptfDevGen | 561 | 0 | 0 | 3.2x |
| IntcSST | 1,672 | 0 | 0 | 9.7x |
| SurfacePen | 2,551 | 0 | 0 | 15.6x |
| tcpip | 46,336 | 0 | 57 (52 z3 / 11 axeyum) | 2.8x |

~56k real queries, **0 verdict disagreements**. On tcpip the unknown-splits cut
in axeyum's favor (z3 hit its own 250 ms timeout more often than axeyum). Large
drivers (tcpip, dxgkrnl) are reproducible via `--full-drivers`.

## Findings

1. **axeyum is correct across the whole workload** -- 230/230 primitives, all
   formula families, and ~56k real driver queries, with zero verdict
   disagreements.
2. **The cold-speed win is structural, not incidental** (Tier 1b): it is the
   fixed FFI/context floor z3 pays per call, largest exactly on the small-formula
   distribution binary analysis produces.
3. **The warm path is the real lever** (Tier 2): ~8x beyond axeyum one-shot on a
   narrowing path condition -- the mechanism behind the 2.8-15.6x real-driver
   numbers.
4. **The historical run surfaced a glaurung z3-adapter soundness bug** (Tier 0): at
   >64 bits, `z3_backend.rs:122` truncates constants via `value as u64`,
   yielding a wrong verdict; axeyum's full-width path was correct. This was a
   Glaurung-adapter limitation, not a Z3-core bug, and was fixed in `4ae96cf`.
   The historical head-to-head timing remains scoped to <=64b; the current
   harness treats both backends as required-correct at 128 bits too.
5. **Methodology, learned the hard way:** an earlier ad-hoc sweep reported
   inflated tcpip/dxgkrnl speedups because ~733 queries were fast-*erroring* on a
   since-fixed concat-width bug, not solving. This benchmark instruments
   unknown/error per backend precisely so that trap is visible. Verdict
   agreement alone is never sufficient.

## Threats to validity / honest caveats

- **Single-run timing.** These are median-of-N per harness but a single process
  run per tier; they are strong signal, not variance-gated. The repeated,
  RSS/variance-gated contract lives separately in
  `../capture/lineage_gate.py`. Use that for regression gating.
- **z3 via the `z3` crate**, one fresh solver per call -- this *is* glaurung's
  real integration, but a z3 embedding that reused a context would show a
  smaller floor. The comparison is "as glaurung uses them."
- **Tier 3 is z3-authoritative** (z3 drives exploration), which isolates solver
  cost fairly but means the stream reflects z3's model choices.
- **Widths >64b in the historical files** exercised the then-known-unsound Z3
  adapter path and were excluded from that run's timing head-to-head. Current
  runs include those widths after the adapter fix.
- **Synthetic tiers (0/1/1b/2)** are author-constructed; they explain *mechanism*
  and *correctness*. The real-workload claims rest on Tier 3.

## File map

```
docs/history/axeyum-integration-2026-07/benchmark/
  README.md                 <- this file
  REVIEWER-CHECKLIST.md     <- skeptical-reviewer self-critique

bench/axeyum/
  run_benchmark.sh          <- reproducible orchestrator (provenance-stamped)
  results/
    provenance.txt          <- git revs, host, CPU, rustc, date
    tier0-primitives.jsonl  <- machine-readable per-cell (op,width,verdict,correct,us)
    tier0-primitives.table.txt
    tier1-families.txt
    tier1b-sweep.txt
    tier2-incremental.txt
    tier3-drivers.txt
```

Harnesses live in `examples/axeyum_bench_primitives.rs` (new, Tier 0),
`axeyum_diff.rs` (Tier 1), `axeyum_sweep.rs` (Tier 1b),
`axeyum_incremental.rs` (Tier 2), `ioctlance.rs` (Tier 3).

## Before submission

See `REVIEWER-CHECKLIST.md` -- a self-review from a skeptical PC-reviewer's
perspective, with 10 prioritized todos (problem / evidence required / what to
build) that must be addressed before the performance claims are defensible. The
critical four: a warm z3 baseline (not one-shot-over-FFI), per-query paired
statistics (geomean + CIs, not ratio-of-sums), solved-only timing (the "faster"
number is confounded with timeouts), and end-to-end finding-parity under
axeyum-authoritative mode.
