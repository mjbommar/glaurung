# Solver ADR-036 — The pin at the canonical cache and the kept trail: ADR-2145 measured in production, and the library cache consumed (item 5)

> **Kind:** decision · **Status:** maintained

**ADR status:** Measured and implemented 2026-09-17; `solver-002`'s perf gate is
**still not met** on this evidence; no default changes.
**Context:** [`solver-035`](solver-035-warm-fix-repin-and-model-preference.md)
re-pinned at Axeyum's quadratic-term fix (ADR-2142) and left two things
open. First, its own closing table: warm Axeyum's per-check p90 on DptfDevGen
still grew 0.09 → 6.1 ms across a 1,229-check session, the linear term
ADR-2142 named as its follow-up (the incremental core re-derived the whole
assignment on every solve), so warm Axeyum crossed cold Axeyum's p90 near
age 550 and summed to 1.51 s against warm z3's 0.20 s. Second,
improvement-list item 5 — ADR-0303's canonical constraint-cache identity in
the adapter — was "waiting on Axeyum". Both landed the same morning:
Axeyum ADR-2145 keeps the surviving scopes' trail across `pop` and `check`
(CaDiCaL `ilb`-style longest-common-prefix backtracking plus z3's re-init
list; replayed DptfDevGen session 1.21 → 0.45 s; ON by default,
`AXEYUM_WARM_KEEP_TRAIL=off` is the old schedule), and Axeyum ADR-2144
makes the canonical constraint cache a library feature of
`IncrementalBvSolver` (`SolverConfig::canonical_constraint_cache`, OFF;
`AXEYUM_CANONICAL_CACHE`), keyed by the sorted, duplicate-elided set of live
assertion identities — inside one hash-consed arena a `TermId` IS the
structural identity, so the key needs no hashing — serving an exact `sat`
only after its model replays against the live set, an exact `unsat`
directly, `unsat` for any live superset of a cached unsat set, and a cached
model of a subset when it replays; `unknown` never cached; counters on
`stats()`. Axeyum's sizing note
(`docs/research/11-design-review/2026-09-17-constraint-cache-sizing.md`)
had already found that Glaurung's own cache (`constraint_cache.rs`) is not
"ordered query text" but the ADR-0303 identity — the SHA-256 of each
assertion's SMT text, sorted and deduplicated — process-wide across arenas,
and measured 418 of 1,206 checks (34.7 %) as exact canonical reuse within
one DptfDevGen owner session. ADR-2144's last section says what Glaurung
should do: turn the engine's cache on for the path-owned warm solver, read
`stats().cache_hits` beside `replay_sat_cache_stats()`, and keep the
process-wide cache only for the cross-path share.
**Decision:** Three things, on one branch.
1. *Bump the pin* to `43f1e0f9038de389d7b1a88b9d3b507ed3c6255d` (Axeyum
   `origin/main`, 2026-09-17 08:46), keeping `default-features = false,
   features = ["qfbv"]`. No adapter change: both solver feature sets
   compile with 0 errors; `cargo test --features solver-axeyum
   --no-fail-fast` gives 36 binaries, 5,258 passed / 1 failed / 19 ignored —
   solver-035's 5,253 plus, by name, the five item-4 tests `46799b9a` added
   after that count was taken, and the same single pre-existing `ir::ast`
   decompiler failure; the shadow-split replay holds the 135-row floor
   (0 failures, 0 open gaps, median 964 ms, max 2.8 s, debug build).
2. *Re-measure the sizing and the tier at this pin*, same command, same
   ceiling, so ADR-2145's number comes from the production topology.
3. *Consume the library cache* (item 5). `GLAURUNG_AXEYUM_CANONICAL_CACHE`
   (`on` | `off`) is read once and forwarded to
   `SolverConfig::canonical_constraint_cache` by
   `axeyum_backend/config.rs::build_config`, which every Axeyum session this
   adapter creates goes through — so the path-owned warm solvers (snapshot,
   lineage, direct-delta, and the session a reset rebuilds) carry the
   engine's cache. Unset keeps Axeyum's own default (OFF unless the process
   carries `AXEYUM_CANONICAL_CACHE`); a malformed value refuses to run. The
   four counters are folded from each session's `stats()` around every warm
   check into process counters (`canonical_cache_stats()`), printed by
   `examples/ioctlance` as `[axeyum-canonical-cache]`; the Axeyum-only
   build — the only one Glaurung's own `GLAURUNG_ENGINE_CONSTRAINT_CACHE`
   wrapper runs in, since it refuses a `solver-z3` build — also prints
   `[engine-cache]`, so an A/B of the two caches reads both from one
   stderr. **The default does not move.**

**Evidence:**

*The sizing, same command as solver-034/035* (`tools/axeyum/shadow_capture.py`,
`--release --example ioctlance --features solver-z3,solver-axeyum`,
`sqfs-intel-DptfDevGen.sys`, 60 s ceiling, default 250 ms check timeout,
host s4 at load 7–8 with other lanes active; a scratch `--root` so a split
could not land in the tree):

| measure | solver-035 at `11b895a35` | this record at `43f1e0f90` |
|---|---:|---:|
| wall time | 6.0 s | **5.6 s** (4.8 s in the tier run) |
| checks (`[shadow-diff] queries=`) | 1,388 (agree 1,388) | 1,388 (agree 1,388) |
| split occurrences / distinct scripts | 0 / 0 | 0 / 0 |
| `[exploration-limits]` | `runs=8 completed=7 state_budget=1 deadline=0` | same |
| same-stream, in process | z3 2,198 ms, Axeyum 1,516 ms | z3 2,212 ms, **Axeyum 517 ms** |
| max RSS | 149 MiB | 143 MiB |

*Per-check warm latency by session age*, from the same run with
`GLAURUNG_ORDERED_TRACE_DIR` set (1,388 checks, 8 warm owners, the largest
serving 1,229; band = 50 checks of the owner's age; milliseconds;
solver-035's values in parentheses):

| age band | n | warm Axeyum p50 | warm Axeyum p90 | warm max | cold Axeyum p90 | warm z3 p90 |
|---:|---:|---:|---:|---:|---:|---:|
| 0–49 | 202 | 0.016 (0.015) | 0.045 (0.086) | 0.57 (0.59) | 0.47 (0.47) | 0.15 (0.15) |
| 250–299 | 50 | 0.085 (0.38) | 0.77 (1.49) | 0.87 (1.58) | 1.63 (1.56) | 0.24 (0.24) |
| 500–549 | 50 | 0.107 (0.85) | 1.09 (2.60) | 1.24 (2.75) | 2.23 (2.19) | 0.25 (0.27) |
| 750–799 | 50 | 0.126 (1.23) | 1.63 (3.70) | 1.79 (4.11) | 2.03 (2.05) | 0.26 (0.32) |
| 1000–1049 | 50 | 0.140 (1.82) | 2.08 (5.28) | 2.21 (5.92) | 2.66 (2.75) | 0.26 (0.32) |
| 1200–1249 | 29 | 0.115 (2.18) | 2.37 (6.10) | 2.40 (6.41) | 1.95 (2.01) | 0.28 (0.27) |

Summed over the process: warm Axeyum 0.52 s (p99 2.4 ms, max 7.0 ms, 0
unknowns; solver-035: 1.51 s, p99 6.0, max 7.3), cold Axeyum 2.01 s (2.00),
warm z3 0.19 s (0.20). The p50 growth is gone (0.016 → 0.115 ms across the
session where it was 0.015 → 2.18: the delta of a check, not the database);
the p90 still grows linearly but at 0.4× the old slope, and warm Axeyum now
stays under cold Axeyum's p90 in every band — solver-035's crossing near
age 550 no longer happens. What remains at p90 is the sibling check's
genuinely new cone and the `assignment_is_model` pass ADR-2145 names; the
same-stream ratio against warm z3 on this driver is now 2.7× (0.19 s against
0.52 s; solver-035: 7×; July's preregistered warm ratio was 0.84).

*The four-driver tier* (`scripts/shadow-capture.sh --binary …`, the full
five stages, same host): **5 min 42 s**, 44,604 checks, 0 disagreements, 0
malformed, **0 split occurrences, 0 new scripts**, floor 135 of 135 replayed
(0 failures, 0 open gaps; median 920 ms, max 2.6 s, debug). Per driver (wall,
checks, same-stream z3 / warm Axeyum, `deadline=`): DptfDevGen 4.8 s /
1,388 / 2.11 s / 0.51 s / 0; vwififlt 56.8 s / 17,846 / 19.3 s / 4.98 s / 0;
IntcSST 47.3 s / 8,763 / 22.5 s / 3.27 s / 0; SurfacePen 99.0 s / 16,607 /
34.9 s / 4.78 s / 1. Against solver-035 (6 min 24 s, 44,069 checks, 1 split):
the one `z3:wall-timeout` split on SurfacePen did not recur in this run, and
SurfacePen's `deadline=1` is unchanged since the old pin (solver-033); the
535 extra checks are SurfacePen's exploration getting further inside the
same ceiling. Only the header line of `verdicts.tsv` (the pin the Axeyum
column was measured at) changed.

*Item 5, the library cache versus Glaurung's own* — ADR-0303's question
("is a cache additive over the warm solver?") measured with the cache
inside the warm solver. Two builds, because Glaurung's cache cannot run in
the fair-shadow one.

(a) Fair-shadow, `solver-z3,solver-axeyum`, the sizing command, arms
interleaved and alternating in order; the "off" arm is today's shipped
configuration (the lever unset; Glaurung's own cache is off by default and
refused in this build):

| driver | pair | arm | warm Axeyum summed | wall | `cache_hits` | `cache_superset_hits` | `cache_replay_rejections` | ADR-0190 replay-cache hits | `disagree` | different-model |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| DptfDevGen | 1 | off | 649 ms | 5.22 s | 0 | 0 | 0 | 500 | 0 | 313 |
| | 1 | on | **366 ms** | 4.82 s | 744 | 0 | 628 | 0 | 0 | 231 |
| | 2 | on | 355 ms | 4.73 s | 744 | 0 | 628 | 0 | 0 | 231 |
| | 2 | off | 545 ms | 5.15 s | 0 | 0 | 0 | 500 | 0 | 313 |
| | 3 | off | 543 ms | 5.10 s | 0 | 0 | 0 | 500 | 0 | 313 |
| | 3 | on | 352 ms | 4.83 s | 744 | 0 | 628 | 0 | 0 | 231 |
| vwififlt | 1 | off | 5,254 ms | 58.7 s | 0 | 0 | 0 | 6,537 | 0 | 10,932 |
| | 1 | on | **2,796 ms** | 54.9 s | 12,767 | 893 | 4,996 | 0 | 0 | 10,788 |
| | 2 | on | 2,818 ms | 55.5 s | 12,767 | 893 | 4,996 | 0 | 0 | 10,788 |
| | 2 | off | 5,112 ms | 56.9 s | 0 | 0 | 0 | 6,537 | 0 | 10,932 |

1,388 and 17,846 checks in every run, 0 unknowns, `[exploration-limits]`
identical between arms. Medians: DptfDevGen 545 → 355 ms (−35 %), hits 744
of 1,388 (53.6 %); vwififlt 5,183 → 2,807 ms (−46 %), hits 12,767 of 17,846
(71.5 %), 893 of them `unsat` served for a superset. The cache sits in front
of ADR-0190's ordered replay-checked cache and absorbs every hit it was
serving (500 → 0, 6,537 → 0) plus the reordered, re-scoped and
model-reuse ones it could not. `decided_disagreement` against cold z3 is
**0 in all ten runs**. The rejection count is high by design: a reuse
candidate is the model of a subset tried against the extending assertion,
and on a sibling branch that assertion is the negation. Served models
coincide with z3's more often (313 → 231, 10,932 → 10,788 of the both-sat
checks) because a cached model is the first one found, which is what z3's
deterministic search also tends to return.

(b) Axeyum-only, `--release --example ioctlance --features solver-axeyum`
(the production dispatch: adaptive lineage, no z3), same fixed environment
minus `GLAURUNG_FAIR_SHADOW`, five arms × three rounds with the order
rotated per round; `[solver] solver_time` is the summed backend time,
wall is the whole process:

| driver | arm | backend solves | solver time (3 rounds) | wall (3 rounds) | cache hits |
|---|---|---:|---|---|---|
| DptfDevGen | off / off (today) | 1,376 | 441 / 427 / 433 ms | 0.51 / 0.48 / 0.50 s | — |
| | Glaurung `exact` | 835 | 416 / 397 / 397 ms | 0.70 / 0.68 / 0.67 s | 541 exact-sat of 1,376 lookups, 541/541 replays |
| | Glaurung `structural` | 834 | 393 / 399 / 432 ms | 0.68 / 0.69 / 0.72 s | 541 + 1 sat-superset |
| | library `on` | 1,376 | **271 / 274 / 325 ms** | **0.32 / 0.33 / 0.39 s** | 741 of 1,376 (619 rejections) |
| | both | 834 | 260 / 273 / 270 ms | 0.54 / 0.57 / 0.56 s | 541 + 1 outside, 208 inside |
| vwififlt | off / off (today) | 18,042 | 4,333 / 4,161 / 3,874 ms | 4.58 / 4.39 / 4.09 s | — |
| | Glaurung `exact` | 7,892 | 2,954 / 2,698 / 2,695 ms | 7.06 / 6.73 / 6.66 s | 10,436 (9,243 sat + 1,193 unsat) of 18,328 |
| | Glaurung `structural` | 7,069 | 2,890 / 2,832 / 3,047 ms | 8.53 / 8.47 / 8.84 s | 11,259 (+49 sat-superset, +780 unsat-subset) |
| | library `on` | 18,328 | **2,327 / 2,348 / 2,316 ms** | **2.55 / 2.58 / 2.54 s** | 13,150 of 18,328 (937 superset, 5,095 rejections) |
| | both | 7,079 | 1,700 / 1,769 / 1,720 ms | 7.29 / 7.48 / 7.18 s | 11,259 outside, 2,575 inside |

Verdict identity, by query content through `GLAURUNG_ORDERED_TRACE_DIR` (one
traced run per arm): DptfDevGen's three arms issue the identical 1,376-check
sequence (sat 893 / unsat 483) with **0 disagreements**; on vwififlt the two
cache arms issue 18,328 checks where the off arm issues 18,042, because a
served `sat` returns the cached model, concretization follows it, and the
exploration diverges (the library arm from check 21 — model reuse serves a
subset's model on a first-seen set — Glaurung's from check 11,019); over the
9,083–9,291 queries common by content, and between the two cache arms,
**0 verdict disagreements**. The findings output is empty in every arm of
both drivers (every raw finding is suppressed ArgN noise), so it is not a
control and is not claimed as one.

*Item 5's tests* (`axeyum_backend::tests`): the parse table; the setting
reaching `SolverConfig` with the timeout and model preference still riding
along; the process lever read in a child process per value, `1` making the
child fail; and a retained session under the cache — `x + y = 10, x < 4,
y > 5` checked, checked again, and re-asserted after a pop in the other
order — 1 miss then 2 hits (the key is the set, which ADR-0190's ordered
key misses on), every served model replays by concrete evaluation and is the
cached one, and the same session with the cache off counts nothing.

**Consequences:**

*Can the library cache replace Glaurung's own for the per-path case?* Yes,
and it already dominates it. On both drivers, in the only build Glaurung's
cache can run in, Glaurung's cache saves backend time and loses more wall
than it saves (DptfDevGen 0.50 → 0.68 s, vwififlt 4.4 → 6.7–8.5 s: the SMT
text rendering plus SHA-256 per assertion per lookup, ADR-0304's July
finding reproduced at this pin), while the library cache saves both
(0.50 → 0.33 s, 4.4 → 2.55 s), sees more of the repeats (741 vs 541 of
1,376; 13,150 vs 10,436–11,259 of 18,328) because it keys inside the arena,
adds model reuse and unsat-superset service, and changes no verdict.
Stacking both is the worst of each. Glaurung's own cache stays what it is
today — off, an experiment behind `GLAURUNG_ENGINE_CONSTRAINT_CACHE` whose
only consumer is ADR-0303's factorial replay — and nothing in this record
removes it, because the cross-path share is the one thing the library cache
cannot see.

*What the library cache cannot do.* It is per solver, so per path-owned
session: an assertion set that repeats on a DIFFERENT owner (the sizing
note's gap between 34.7 % within-owner and ADR-0304's 62 % per pass, most
of it cross-owner) is invisible to it; cross-arena reuse needs a structural
term hash in `axeyum-ir` and a symbol-name-keyed model, which is ADR-2144's
named next slice, not this one. These counters cannot split Glaurung's hits
into within- and cross-owner, so the cross-owner share on these drivers is
not measured here. It does not implement ADR-0303's `Q ⊆ C` `sat`
direction (bounded at 4.4 % by ADR-0304's v2 artifact), does not hand back
unsat cores, and — the property that decides the default — a served `sat`
is the cached model, so turning it on moves the exploration (18,042 →
18,328 checks on vwififlt) and would invalidate every pinned model-choice
trace, the same objection solver-035 recorded against making `zero` the
default.

For `solver-002`'s gate: the linear term solver-035 measured is gone in
production, and the DptfDevGen same-stream ratio moved from 7× to 2.7× (and
with the library cache on, pair 2 reads 2,124 ms z3 against 355 ms warm
Axeyum, 0.17× on the same stream); the gate is still **not met** on this evidence — one
driver's sizing plus a two-driver A/B, unpreregistered, on a loaded host.
ADR-0272's campaign at this pin, with `GLAURUNG_AXEYUM_CANONICAL_CACHE=on`
as a registered arm, is the next step, not a default flip. Items 1–9 of the
improvement list are done; item 10 is cindergraph's Milestone H.
`benches/ir_dataflow.rs` still breaks every `cargo check --all-targets` lane
of `scripts/feature-build-gate.sh` on master, unchanged by this record.

**Alternatives rejected:** shipping `GLAURUNG_AXEYUM_CANONICAL_CACHE=on`
as the adapter's default on this A/B (it changes which model every repeated
`sat` returns and so the exploration itself; the finding-parity sweep and
the preregistered campaign have not run under it); deleting
`constraint_cache.rs` now that the engine has the identity (its cross-arena
key is the only route to the cross-owner share until `axeyum-ir` has a
structural hash, and ADR-0303's replay depends on it); pointing Glaurung's
wrapper at the library counters so the ADR-0303 factorial could run its
`exact`/`structural` modes with the library cache (ADR-2144 suggests it;
the factorial harness pins Glaurung's cache stages and stage sums, and
rewiring it is a separate change to a preregistered protocol); reporting
the findings digest as the verdict control (it is empty on every arm).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
