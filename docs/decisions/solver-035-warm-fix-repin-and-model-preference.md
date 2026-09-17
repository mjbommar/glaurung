# Solver ADR-035 — The pin at the warm-session fix: the sizing re-measured, and the model-preference knob consumed

> **Kind:** decision · **Status:** maintained

**ADR status:** Measured and implemented 2026-09-17; `solver-002`'s perf gate is
**measurable again and still not met**; no default changes.
**Context:** [`solver-033`](solver-033-six-cell-rerun-at-the-2026-09-16-pin.md)
found that at pin `8df853252` warm Axeyum's per-check latency grew with the
retained session's age (DptfDevGen p90 0.1 ms in a session's first 50 checks,
178 ms past 500), pushing every campaign process into the frozen 60 s solve
budget so the preregistered analyzer could not treat the work as fixed, and
asked for one number: the same measurement at a pin where warm latency is flat.
[`solver-034`](solver-034-continuous-shadow-split-capture-tier.md) sized the
capture tier at that pin (59.5 s wall for DptfDevGen, 15 split scripts, all
`axeyum:wall-timeout` at the 250 ms cap) and noted the "capability gaps" it
surfaced were that latency crossing the cap. Axeyum bisected the growth to the
commit that made its native CDCL core the warm engine — the target-phase
snapshot re-walked the whole trail at every decision, O(decisions × retained
trail) per check — and fixed it with stable-prefix marks (Axeyum ADR-2142; the
replayed DptfDevGen session's last band 306 ms → 7.5 ms p90). The same span
landed `ModelPreference { Any, PreferZero, LeastUnsigned }` on `SolverConfig`
(Axeyum ADR-2140), the knob improvement-list item 4 was waiting on.
**Decision:** Three things, on one branch.
1. *Bump the pin* to `11b895a35dc583ea593f1dd6cd2412b8ef9387fa` (Axeyum
   `origin/main`, 2026-09-17, 34 commits past `8df853252`), keeping
   `default-features = false, features = ["qfbv"]`. No adapter change: both
   solver feature sets compile with 0 errors; `cargo test --features
   solver-axeyum --no-fail-fast` gives the same 36 binaries, 5,253 passed /
   1 failed / 19 ignored as solver-032, with the same single pre-existing
   `ir::ast` decompiler failure; the shadow-split replay holds the 134-row
   floor (0 failures, 0 open gaps, median 912 ms, max 2.7 s, debug build).
2. *Re-measure the tier's sizing on the same driver, same command, same
   ceiling*, and run the four-driver tier once, so the number solver-033 asked
   for comes from the production topology and not from Axeyum's replay.
3. *Consume the model preference.* `GLAURUNG_AXEYUM_MODEL_PREFERENCE`
   (`any` | `zero` | `least-unsigned`) is read once and forwarded to
   `SolverConfig::model_preference` by `axeyum_backend/config.rs::build_config`,
   which every Axeyum session this adapter creates goes through (one-shot,
   profiled, warm, direct-delta), so the warm engine's `check`/`check_assuming`
   return the finished model too. Unset keeps Axeyum's own default (`Any`,
   the search byte-for-byte as shipped); a malformed value refuses to run, as
   `GLAURUNG_CONCRETIZATION_POLICY` does. **The default does not move**, and
   the knob is not a concretization policy: it changes which model the
   backend hands the explorer, not the policy ID the trace records
   ([`architecture/solver/concretization-policy.md`](../architecture/solver/concretization-policy.md)).

**Evidence:**

*The sizing, same command as solver-034* (`tools/axeyum/shadow_capture.py`,
`--release --example ioctlance --features solver-z3,solver-axeyum`,
`sqfs-intel-DptfDevGen.sys`, 60 s ceiling, default 250 ms check timeout, host
s4 at load 3–5 with other lanes building):

| measure | solver-034 at `8df853252` | this record at `11b895a35` |
|---|---:|---:|
| wall time | 59.5 s | **6.0 s** |
| checks (`[shadow-diff] queries=`) | 1,388 (agree 1,388) | 1,388 (agree 1,388) |
| split occurrences | 33 | **0** |
| distinct split scripts published | 15, all `axeyum:wall-timeout` | **0** (no capture directory) |
| `[exploration-limits]` | `deadline=1` (solver-033) | `runs=8 completed=7 state_budget=1 deadline=0` |
| same-stream, in process | — | z3 2,198 ms, Axeyum 1,516 ms |
| max RSS | 147 MiB | 149 MiB |

The wall time was the 60 s per-function ceiling; it is now the driver. The
root dispatch function no longer reaches the budget, so the fixed-work
precondition ADR-0272's analyzer refused on in solver-033 is restorable.

*Per-check warm latency by session age*, from a second identical run with
`GLAURUNG_ORDERED_TRACE_DIR` set (1,388 checks, 8 warm owners, the largest
serving 1,229; band = 50 checks of the owner's age; milliseconds):

| age band | n | warm Axeyum p50 | warm Axeyum p90 | warm max | cold Axeyum p90 | warm z3 p90 |
|---:|---:|---:|---:|---:|---:|---:|
| 0–49 | 202 | 0.015 | 0.086 | 0.59 | 0.47 | 0.15 |
| 250–299 | 50 | 0.38 | 1.49 | 1.58 | 1.56 | 0.24 |
| 500–549 | 50 | 0.85 | 2.60 | 2.75 | 2.19 | 0.27 |
| 750–799 | 50 | 1.23 | 3.70 | 4.11 | 2.05 | 0.32 |
| 1000–1049 | 50 | 1.82 | 5.28 | 5.92 | 2.75 | 0.32 |
| 1200–1249 | 29 | 2.18 | 6.10 | 6.41 | 2.01 | 0.27 |

Summed over the process: warm Axeyum 1.51 s (p99 6.0 ms, max 7.3 ms, 0
unknowns), cold Axeyum 2.00 s, warm z3 0.20 s. Against solver-033's rep 1 on
the same driver (warm Axeyum 37.6 s, p90 178 ms past 500 checks, 51 cells at
the cap): the quadratic term is gone and warm Axeyum is again cheaper than
cold Axeyum over the process. What remains is the linear term ADR-2142 names
as its follow-up — the incremental core re-propagates from an empty
assignment on every solve — visible as warm p90 growing 0.09 → 6.1 ms over
1,200 checks while warm z3 stays at 0.15–0.32 ms, and crossing cold p90 near
age 550.

*The four-driver tier* (`scripts/shadow-capture.sh --binary …`, the full
five stages, same host): 6 min 24 s
for the four drivers, **44,069 checks, 0 disagreements, 0 malformed**, 1
split occurrence, **1 distinct split script**, and the floor held (134 of 134
replayed, 0 failures, 0 open gaps; the new row promoted, so the floor is now
**135**). Per driver (wall, checks, splits, `[exploration-limits]`):
DptfDevGen 7.2 s / 1,388 / 0 / `deadline=0`; vwififlt 65.9 s / 17,846 / 0 /
`deadline=0`; IntcSST 50.5 s / 8,763 / 0 / `deadline=0`; SurfacePen 103.2 s /
16,072 / 1 / `deadline=1`. Against solver-034's first run at `8df853252`
(7 min 50 s, 41,493 checks, 27 new scripts, 26 of them `axeyum:wall-timeout`):
the 26 Axeyum-side timeouts are gone, and the one split that remains is
`z3:wall-timeout` on SurfacePen -- the same content hash
(`4d9952c9…`) the `surfacepen-60s-17ff038` capture already holds, z3 at
the 250 ms cap and Axeyum deciding it (`sat`, 126 ms in the replay) -- so it
is a stable z3-side nondecision, not an Axeyum gap. SurfacePen's `deadline=1`
was also 1 at the old pin (solver-033: every process), where cold Z3 and
cold Axeyum each cost 26-29 s on that driver; it is not the warm regression.
The capture is committed as `surfacepen-60s-46799b9/`.

*Item 4* (`axeyum_backend::tests`): the parse table
(`model_preference_parses_the_three_spellings_and_refuses_the_rest`); the
setting reaching `SolverConfig` for all three variants with the timeout still
riding along (`model_preference_reaches_the_solver_config`); the process
lever read in a child process per value, `sideways` making the child fail
(`model_preference_env_is_read_once_and_a_malformed_value_is_refused`); and
Axeyum's three-witness shape built from Glaurung expressions — under `zero`
the one-shot backend returns `y = 0xF4` where `Any` returns another of
{0xF4, 0xF5, 0xF6}, and the lifted model replays by concrete evaluation and
by a pinned re-solve (`a_sat_model_under_zero_is_least_and_replays`).
Mutation control: running that test's second solve under `Any` kills exactly
it. The cost of `zero` on a driver workload: measured on
DptfDevGen with the sizing command, arms interleaved `any`/`zero` three
times: summed warm Axeyum time 1,516 / 1,749 / 1,521 ms under `any` against
1,628 / 1,537 / 1,538 ms under `zero` (medians 1,521 vs 1,538, +1 %, inside
the run-to-run spread), wall 6.0-6.7 s in both arms, 1,388 checks and 0
unknowns in every run, and `different-model` (both-sat models that differ
from z3's) 313 → 283 of 895 in all three pairs. On this driver the shrink is
free at the process level and moves 30 of 895 models toward z3's; ADR-2140's
+12 % was measured on the SMT-LIB QF_BV benchmark set, whose `sat` instances
are far larger than a driver check.

**Consequences:** For `solver-002`'s gate: the obstacle solver-033 named is
removed — warm Axeyum no longer pushes DptfDevGen into the 60 s budget, so
ADR-0272's fixed-work campaign can be re-registered at this pin and produce a
preregistered verdict — but the gate itself is **not met** on this evidence.
The same-stream ratio on DptfDevGen puts warm z3 at roughly 7× warm Axeyum in
summed time (0.20 s against 1.51 s; July's preregistered warm ratio on this
driver was 0.84), and that is one driver, unpreregistered, on a loaded host.
The next step is the campaign itself, not a default flip. The tier's weekly
population changes character: at `8df853252` its new rows were the warm cap
firing; at this pin a new row is more likely a real capability gap, which is
what the tier exists to surface. `GLAURUNG_AXEYUM_MODEL_PREFERENCE=zero` is
available for the finding-parity sweep ADR-2140 anticipates (the July
measurement: 79 % of both-sat queries returned different valid models, and
every finding-set difference traced to `concretize_addr`); nothing here runs
that sweep. Item 5 (ADR-0303's canonical constraint-cache identity) still
waits on Axeyum's cache item. `benches/ir_dataflow.rs` still breaks every
`cargo check --all-targets` lane of `scripts/feature-build-gate.sh` on
master, unchanged by this record.

**Alternatives rejected:** flipping `solver-axeyum` to a default on the
sizing alone (one driver, one run, no preregistration — solver-002 reads a
preregistered warm ratio, and this record's ratio is 0.13 on that driver);
re-running ADR-0272's campaign inside this lane (it is a 50-minute
registered protocol with its own record, and its precondition is what this
record establishes); making `zero` the adapter's default because the shrink
is cheap (ADR-2140 measured +12 % wall on QF_BV for a model change no
Glaurung finding has yet been shown to need; the six-cell matrix of
ADR-0262 was crossed on the explorer-side policy, and a default that changes
every model would invalidate every pinned model-choice trace); mapping
`GLAURUNG_CONCRETIZATION_POLICY=min-unsigned` onto the backend knob
automatically (the ladder is exact and backend-agnostic, the shrink is a
local minimum of one backend's model; conflating them would let the
Axeyum-only knob change a policy ID every trace pins).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
