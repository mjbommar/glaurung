# Solver ADR-033 — The rerun at the 2026-09-16 pin: inconclusive under ADR-0272, and warm Axeyum is the reason

> **Kind:** decision · **Status:** maintained

**ADR status:** Measured 2026-09-17; `solver-002`'s perf gate is **not met**;
no default changes.
**Context:** [`solver-002`](solver-002-axeyum-as-default-backend.md) makes
Axeyum the default backend on one condition, "not yet perf-parity with z3"
becoming parity, and the only measurement of that condition was Axeyum
ADR-0272's six-cell campaign of 2026-07-19 at pin `a9abc6cdc`: warm Z3/Axeyum
0.84 / 1.05 / 2.23 / 2.28 on DptfDevGen / vwififlt / IntcSST / SurfacePen.
[`solver-032`](solver-032-axeyum-pin-bump-and-shadow-corpus-prune.md) moved
the pin to `8df853252` (11,607 commits later, BatSat retired for Axeyum's own
SAT core) and left the number unmeasured. Improvement-list item 3 is that
measurement.
**Decision:** Run ADR-0272's protocol unchanged except for the pins a rerun at
head must change (producer revision, executable hash, validator path;
recorded in
[`development/six-cell-rerun-2026-09-17.md`](../development/six-cell-rerun-2026-09-17.md)),
as four cells because Bitwuzla 0.9.1 could not be rebuilt on the host within
the hour. Register with zero result rows, run once, and report the analyzer's
verdict as the verdict. Fix the one producer defect the preflight smoke found
(the engine-cache wrapper had overwritten the fair-shadow timing aliases since
`2c999b67`, so no `solver-z3,solver-axeyum` trace since 2026-07-20 could pass
the producer validator; `b1f420ab`, with a test that fails on the old code)
before registration, as ADR-0272 permits for a runner/schema defect found
before any timing row. Do **not** change the default feature set: that is the
user's decision and this record is its input.
**Evidence:** `bench-results/glaurung-six-cell-neutral-20260917/`. Twenty
fresh processes, all exit 0 and producer-validated; 208,359 ordered check
occurrences, 833,436 measured cells; **0 operational errors, 0 decided
disagreements**, 52 unknowns (51 warm-Axeyum cells at the 250 ms cap on
DptfDevGen, 1 cold-Z3 cell on SurfacePen). The preregistered analyzer
refused every driver — `fixed-work check identity drift` — because one
dispatch root per driver hits the frozen `IOCTLANCE_SOLVE_SECS=60` budget
(`deadline=1` in all 20 `[exploration-limits]` lines) and the cut moves with
wall time; July's processes finished in 6–52 s with identical work. The
budget is hit because warm Axeyum's summed time per process is 37.6 / 54.3 /
36.8 / 40.7 s against cold Axeyum's 2.1 / 31.9 / 14.8 / 26.4 s and warm Z3's
0.2 / 3.7 / 2.6 / 2.9 s: retained topology now costs Axeyum more than it
saves, and its per-check latency grows with the retained session's age (p90
0.1 ms in a session's first 50 checks, 178 ms past 500, on queries that
solve cold in ~2 ms). The exploratory common-prefix ratios (the analyzer's own
functions over the work all five repetitions share; optimistic for Axeyum by
construction) put warm Z3/Axeyum at 0.17 / 0.09 / 0.31 / 1.22 against July's
0.84 / 1.05 / 2.23 / 2.28, and cold Z3/Axeyum at 1.18 / 0.65 / 1.41 / 1.92
against July's 1.16 / 0.70 / 2.79 / 2.58. Load during the run was median 8.2,
max 16.3 on 16 logical CPUs (other lanes building); the warm-pair process CVs
were 0.6–1.2 % on three drivers and 3.9 % on DptfDevGen, so the ratios are
not a load artefact, but a quiet-host repeat would tighten them.
**Consequences:** `solver-002`'s gate is further from closing than in July,
and the reason is specific: Axeyum's *incremental* path at pin `8df853252`,
not its one-shot solving (cold Axeyum still beats cold Z3 on three of four
drivers). That is an Axeyum-side finding with a Glaurung-side reproducer
(`examples/axeyum_incremental.rs` exists; the campaign traces give the exact
query streams). Until a pin where warm Axeyum's latency is flat in session
age, the campaign cannot be fixed-work under its frozen 60 s budget, so the
next rerun needs either that pin or a new preregistration with a
work-bounded rather than wall-bounded budget (the v4 deterministic
measurement schema exists for exactly that). The July integration notes'
"1.7–3.2× slower one-shot" is not what this run measured; one-shot is at
parity or better, and the warm regime is the regression.
**Alternatives rejected:** re-running until the fixed-work gate passes (the
gate failing *is* the result under ADR-0272, and a wall-clock cut cannot be
made to land in the same place by repetition); raising `IOCTLANCE_SOLVE_SECS`
so the work completes (changes a frozen pin after observing results);
reporting the common-prefix ratios as the preregistered result (they are
labelled exploratory and are biased toward young sessions); running on s6 to
escape host load (no `libz3.so` there, and a different CPU from July's);
flipping the default on the cold-cell result alone (`solver-002` reads the
production topology, which is retained sessions).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
