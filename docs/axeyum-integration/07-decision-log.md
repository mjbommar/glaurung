# 07 - Decision log

ADR-style records of the load-bearing choices, so a future reader (or a
future us) sees the reasoning, not just the outcome. Status: all
**Proposed** until the plan is acted on; promote to **Accepted** as each is
implemented.

---

## ADR-001 - Depend on axeyum by path (dev) then git-rev (release)

**Status:** Proposed.
**Context:** All axeyum crates are `publish = false`; nothing is on
crates.io. glaurung needs `axeyum-ir` + `axeyum-solver` (rest transitive).
Both repos are the author's, both edition 2024 / rustc >= 1.88.
**Decision:** Use a **path dependency** during co-development (P1-P3), then
pin a **git-rev dependency** at P4 (the default-landing) so the shipped
artifact is reproducible and decoupled from local checkout paths. Never
crates.io (blocked by `publish=false`; not needed).
**Consequences:** glaurung's MSRV floor rises to rustc 1.88 / edition 2024
(already met). API drift is bounded by keeping the consumed surface tiny
(term building + one-shot solve + model read + proof export).
**Alternatives rejected:** vendoring a copy (drift + license duplication);
crates.io (not published).

## ADR-002 - Axeyum is the default backend; z3 stays an opt-in perf backend

**Status:** Proposed.
**Context:** Axeyum is pure-Rust, wheel-shippable, proof-carrying, but not
yet perf-parity with z3. z3 is fast but links libz3 (C/C++) and is kept
out of the wheel.
**Decision:** Make `solver-axeyum` a **default feature**; keep `solver-z3`
**opt-in**. Priority cascade in `solve()`:
`solver-z3` (if explicitly enabled) -> `solver-axeyum` (default) -> pipe.
**Consequences:** The shipped/default build gets a real pure-Rust
in-process solver (G1). Users who want maximum speed opt into z3. No
silent provider swap - the choice is an explicit build feature.
**Alternatives rejected:** replacing z3 outright (loses the perf escape
hatch while axeyum's perf gate is open, NG1); keeping z3 default (defeats
the pure-Rust/shippability goal).

## ADR-003 - Integrate at the SMT-query seam only, not the executor

**Status:** Proposed.
**Context:** axeyum ships its own `SymbolicExecutor` + BMC + k-induction;
glaurung ships its own `explore.rs` DFS explorer. The two overlap almost
completely in shape.
**Decision:** Consume axeyum **only** as a solver
(`IncrementalBvSolver`/`solve_smtlib` + `Model` + proof export). Do not
adopt axeyum's executor; do not expose axeyum's BMC layer through
glaurung. glaurung builds path conditions; axeyum decides them.
**Consequences:** Minimal coupling, one clear seam (`02`), each project's
executor evolves independently. axeyum's executor remains a useful
*reference* for a future incremental trait (P5), not a dependency.
**Alternatives rejected:** replacing glaurung's explorer with axeyum's
(throws away the x64/WDM detection layer + IOCTLance parity work).

## ADR-004 - MVP is an in-process SMT-LIB text bridge, not a subprocess

**Status:** Proposed.
**Context:** glaurung's `pipe` backend shells out to an SMT-LIB solver
binary. axeyum has **no** stdin `sat/unsat` CLI - only the `axeyum-bench`
harness. But axeyum exposes `solve_smtlib(&str, &config)` as a library fn,
and glaurung's `pipe::build_script` already renders the exact SMT-LIB2.
**Decision:** The P1 walking skeleton is an **in-process** backend that
renders with glaurung's existing serializer and calls `solve_smtlib` -
no subprocess, no CLI shim, no term translator. The subprocess route
(20-line shim + `GLAURUNG_SMT_SOLVER`) is a documented fallback only.
**Consequences:** MVP is in-process (a real step toward G1), reuses proven
code on both sides, and yields the first differential + latency data
before committing to the native term translator (P2).
**Alternatives rejected:** building an axeyum SMT-LIB REPL CLI just to fit
the subprocess pattern (more code, subprocess overhead, no benefit).

## ADR-005 - Keep the one-shot `Solver` trait for v1; add incremental later

**Status:** Proposed.
**Context:** The `Solver` trait is one-shot (`check` over the full assert
list); axeyum's perf advantage is *warm incrementality*, which the
one-shot contract cannot exploit.
**Decision:** v1 honors the existing one-shot trait (fresh arena+solver per
`check`). An **incremental** trait extension (push/pop mapping to axeyum's
`IncrementalBvSolver`, exploiting glaurung's fork structure) is a later,
additive, opt-in phase (P5).
**Consequences:** v1 is simple and low-risk but leaves axeyum's main perf
lever on the table - accepted, because correctness/shippability (G1-G3)
come first and the perf lever is real, sequenced work, not a redesign.
**Alternatives rejected:** widening the trait in v1 (couples the shippable
correctness milestone to a larger engine change).

## ADR-006 - Proofs threaded off-trait in v1 (no trait signature change)

**Status:** Proposed.
**Context:** Only axeyum can produce proofs today; the `Solver` trait
returns `SolveResult` with no proof slot. Widening the trait for one
backend is premature.
**Decision:** Surface DRAT proofs via the concrete `AxeyumSolver` type
(a `check_with_proof` method or a stashed last-proof), not via the shared
`Solver` trait, in v1. Revisit a trait-level proof return only if a second
backend gains proofs.
**Consequences:** The reachability/verdict layer that wants "path
infeasible, DRAT-checked" evidence calls the concrete type; the generic
trait stays unchanged, so z3/pipe are unaffected.
**Alternatives rejected:** adding an `Option<Proof>` to `SolveResult` now
(pollutes every backend's return for one producer).

## ADR-007 - Placement: this plan lives in glaurung

**Status:** Accepted.
**Context:** The integration adds a backend *to glaurung*; axeyum is an
unchanged dependency. The agentic-security-bot repo (where the request
originated) explicitly excludes non-method engineering docs.
**Decision:** Keep the design record in `glaurung/docs/axeyum-integration/`.
**Consequences:** Co-located with the code that will implement it. The
Android-hunting side (agentic-security-bot) links to it as the binary
reachability engine, not owns it.

## ADR-008 - Auto warm reuse requires observed same-path reuse

**Status:** Accepted by the repeated gate; default wiring is the next bounded
change.
**Context:** Fixed lineage reuse is faster than Z3 on every repeated held-out
stream, but eagerly retains a solver for paths that may never issue a second
query. GQ9 needs a production admission signal that is observable before paying
the retained arena/AIG/CNF/SAT-state cost.
**Decision:** `GLAURUNG_AXEYUM_WARM_REUSE=auto` solves a path's first query
one-shot while retaining only its numeric explorer-owned path ID. A second query
for the same still-live path promotes its current complete assertion snapshot to
the existing bounded 9-path/512-assertion lineage adapter; later queries reuse
deltas. Terminal/restarted paths erase both probe and solver state. The default
stays off, and explicit `lineage` remains the fixed control.
**Consequences:** Single-check paths cost one set entry rather than a solver,
while repeated paths sacrifice their first reuse opportunity. Separate probe and
activation counters make the tradeoff measurable. Promotion still performs
original-term model replay inside Axeyum; path/assertion caps still fall back
one-shot. Accept or reject only after fixed-work SurfacePen and NETwtw10
comparison against off and lineage.
**Alternatives rejected:** formula-size thresholds repeat GQ4's unmeasured-cost
mistake; eager first-check retention cannot distinguish singletons; sharing a
mutable solver across siblings violates the accepted lineage ownership model.

**Initial real evidence (2026-07-16):** One same-binary SurfacePen triplet keeps
all 2,551 checks/findings identical. Off is 1.995 seconds Axeyum / 64,228 KiB;
auto is 1.154 seconds / 65,136 KiB with 358 probes and 191 activations; fixed
lineage is 1.062 seconds / 82,480 KiB. One fixed-budget NETwtw10 auto process
keeps all 28,356 checks/findings identical, partitions them exactly into 17,669
warm checks plus 10,687 probes, and records 4,099 activations: 19.595 seconds /
216,016 KiB versus the clean fixed-lineage baseline's 18.751 seconds / 257,632
KiB. Auto trades about 4.5--8.7% Axeyum time for 16--21% lower RSS than lineage
while preserving much of the cold-to-warm gain. Repeat and automate this policy
before any default decision.

**Repeated gate:** The clean three-process-per-driver artifact at Glaurung
`5c4ec0f` and Axeyum `0b77ccff` repeats every exact counter and all 92,721
agreements. Auto measures 1.141 seconds / 65,404 KiB on SurfacePen and 19.554
seconds / 216,580 KiB on NETwtw10. Against the committed lineage baseline,
Axeyum time regresses 7.37%/4.28% while median RSS improves 20.66%/15.93%.
Both time changes exceed ADR-0180's 3% alarm; Z3 also drifts -2.21%/+2.63%, so
cross-run ratio changes are environment-flagged. Keep auto as an explicit
memory-optimized option and retain fixed lineage as the faster opt-in policy;
do not make auto the production default.

## ADR-009 - Assertion exports preserve arbitrary-width truthiness

**Status:** Accepted.
**Context:** Native Z3 and Axeyum deliberately treat every `Assert` as
bit-vector truthiness at the expression's actual width. Concretization can
therefore assert a wide value directly. The shared SMT-LIB renderer and ordered
trace instead compared every assertion with a BV1 literal, and the trace
rejected non-BV1 roots. A real SurfacePen trace exposed the mismatch at event
53 with a 64-bit assertion; this is also the likely source of the capture's
2,225 previously excluded ill-sorted scripts.
**Decision:** Define the producer contract once: expected-true renders
`distinct(term, 0@width)` and expected-false renders `term = 0@width`.
`pipe::build_script`, query dumps, and ordered assertion artifacts share that
renderer. Trace assertions record a positive `assertion_width`; the independent
validator checks it. Native and text bridge tests cover both polarities at
width 64 against zero.
**Consequences:** Text, trace, Z3, and Axeyum now agree without weakening
Axeyum's strict sort checking. Existing query hashes and corpus membership are
not stable across this producer correction and must be regenerated before the
next GQ1/GQ10 baseline. Warm lineage verdict/work counts are expected to remain
semantic controls, but that expectation is not a substitute for rerunning the
exact gate.
**Alternatives rejected:** restricting `Assert` to BV1 would break existing
native concretization behavior; zero-extending a BV1 literal would preserve
the ill-specified equality-to-one semantics for wide values; teaching the
consumer to accept ill-sorted text would conceal a producer defect.

## ADR-010 - Adapt lineage capacity from sustained live-path pressure

**Status:** Accepted as the Axeyum explorer default.
**Context:** ADR-008's second-check policy saves memory but fails the 3% time
alarm because repeated paths pay cold work before rebuilding retained state.
The corrected SurfacePen ordered trace shows that purpose alone is not enough:
address/finding/overflow admission covers 2,285/2,551 checks and retains only
20 singleton paths, but 117 branch-first paths later require warm state. A real
purpose-policy prototype is 1.140 seconds / 72,868 KiB, essentially the same
time as rejected auto and slower than fixed lineage. It was removed. Fixed cap
2 passes SurfacePen but regresses NETwtw10 18.2%, so a universal small cap is
also rejected.
**Decision:** Use pressure-adaptive lineage when
`GLAURUNG_AXEYUM_WARM_REUSE` is unset. It uses the
existing path-owned lineage solver without another query representation or
purpose field. Capacity starts at `min(configured_cap, 2)`. Each failed
low-cap reservation increments a process-wide atomic pressure counter. At 128
events, capacity expands once to the configured hard cap (currently 9); the
triggering check retries reservation immediately. Exact pressure, expansion,
initial-cap, and threshold telemetry enters the fail-closed runner contract.
`off`, `false`, or `0` selects the one-shot override; fixed `lineage` remains
the benchmark control, and explicit `auto`/`snapshot` remain diagnostic modes.
**Consequences:** Low-pressure streams can retain fewer concurrent arenas while
high-pressure streams pay at most 127 initial cap fallbacks before recovering
the proven envelope. Solver/query/model/proof semantics are unchanged: every
warm SAT model is still replayed against original terms, every fallback is the
existing one-shot path, siblings never share mutable state, and the configured
hard cap remains atomic. Single clean calibrations are encouraging but do not
authorize a default: SurfacePen is 1.095 seconds / 81,212 KiB versus a same-
binary cap-9 control at 1.079 seconds / 83,220 KiB; NETwtw10 expands once and
is 18.543 seconds / 261,648 KiB versus 18.740 seconds / 258,764 KiB. All 30,907
checks agree with Z3 with zero unknown splits or resets. Repeat both families
through the versioned runner before deciding GQ9.
**Alternatives rejected:** purpose admission is dominated by cap 1 and still
fails time; fixed cap 1 fails SurfacePen time; fixed cap 2 fails NETwtw10 time;
cap 3 restores SurfacePen time but provides no RSS improvement; formula-shape
analysis would repeat GQ4's paid-analysis failure at the wrong layer.

**Repeated gate:** The clean three-process-per-family artifact at Glaurung
`95c43cb` and Axeyum `f91fb232` repeats exact adaptive topology and all 92,721
agreements. SurfacePen averages 1.085 seconds / 79,424 KiB; NETwtw10 averages
18.558 seconds / 255,364 KiB. The explicit lineage→adaptive comparator reports
Surface Axeyum/ratio/RSS changes of +2.07%/+2.28%/-3.65% and NETwtw10 changes
of -1.03%/-0.89%/-0.88%; Z3 drift is -0.20%/-0.14%. Every 3%/3%/5% plus 2%
alarm passes. The 8,965-byte artifact SHA-256 is
`0255d0ed2a0c5bc078e478cb951561d4de1460c11333a646f3e150b15281e716`.
This accepts adaptive as the GQ9 production admission policy and the Axeyum
explorer default. The default parser and explicit one-shot override have direct
unit coverage. This downstream scheduling choice does not alter Axeyum's
framework-level solver defaults.

## ADR-011 - First-class direct-delta solver session

**Status:** Accepted as the P5 contract plus opt-in explorer-wiring tranche;
production default deferred by ADR-012.
**Context:** The accepted warm lineage adapter proves retained Axeyum state is
the right performance lever, but Glaurung's only framework trait still accepts
`check(pool, complete_snapshot)`. The adapter must retranslate every root and
reconstruct the longest common prefix before it can issue Axeyum push/pop/assert
operations. Axeyum ADR-0201 now exposes an object-safe retained session trait,
but Glaurung still needs an IR-level lifecycle contract.
**Decision:** Add a separate object-safe `IncrementalSolver` trait with
`assert`, `push`, `pop`, `scope_depth`, `check`, and `check_assuming`. Implement
it first as `IncrementalAxeyumSolver`. Each assert translates only the new
Glaurung root, then delegates to Axeyum's retained trait. The session retains
its arena/AIG/CNF/SAT state and keeps symbol mappings in matching frames so
popped scopes and temporary assumptions cannot leak values into later models.
The existing one-shot `Solver`, snapshot adapter, adaptive default, and every
off/fixed/serial control remain unchanged.
**Evidence:** The complete 39-test Axeyum-backend group passes under the 4 GiB
serialized build. A new trait-object test drives a base assertion, scoped SAT
branch, pop underflow, contradictory one-shot assumption, and a subsequent SAT
check proving non-persistence; the scoped SAT model maps back to the exact
Glaurung symbol value. Two additional lineage-transition tests prove that a
retained owner translates only suffix roots, switches siblings by absolute
prefix depth, treats probes as ephemeral assumptions, and fails closed on an
impossible prefix by dropping state and fully rematerializing on the next call.
The explorer-wiring tranche expands that group to 41/41 and adds a deterministic
adapter test covering full materialization, suffix extension, prefix pop,
ephemeral contradictory assumptions, synchronization acknowledgement, and
invalid-partition teardown. Both warm explorer ownership tests pass: forked
owners remain distinct while inheriting only the confirmed depth, and restart
resets ownership and depth.
Warm-profile v7 then makes the entry contract observable rather than
overloading snapshot counters: `entry_mode` and exact persistent/temporary
query, translation, and root-encoding partitions are mandatory. A four-check
direct producer smoke (three SAT, one UNSAT) and a six-check snapshot smoke
both validate at 100% decided through Axeyum's strict v7 summarizer; the direct
summary records two persistent roots and one temporary root translated/encoded
across the exact extension/pop/assumption/reuse sequence.
The first real SurfacePen attempt deliberately exercised direct deltas with the
snapshot-only serial sibling lease and failed the correctness gate: 497/2,551
same-stream verdicts disagreed with Z3. Root cause was exact, not solver
unsoundness: sibling states inherited equal retain depths but had opposite last
branch assertions, so depth-only retention kept the wrong sibling root. Direct
mode now forces serial leasing off and falls back to exclusive LIFO owner
transfer plus distinct sibling sessions. The identical stream then agrees
2,551/2,551 with zero unknowns or replay failures. A pure policy test prevents
the incompatible combination from reappearing.
**Consequences:** Glaurung now drives the real P5 session from explicit path
deltas behind `GLAURUNG_AXEYUM_DIRECT_DELTA=1`. The full query remains intact
for the Z3 authority, ordered capture, and every one-shot fallback. The
explorer advances its prefix marker only on an explicit backend
acknowledgement, so admission fallback, a lost owner, or an operational error
cannot cause a naked suffix to be asserted. The route is not a production
default or a performance claim. Its causal comparison is exclusive-transfer
snapshot versus direct delta; production admission must additionally beat the
current serial-snapshot policy or add a sound source-identity/COW sibling-prefix
contract. Repeated ordered correctness/time/RSS gates remain mandatory.
**Alternatives rejected:** adding default incremental methods to `Solver` would
make one-shot emulation indistinguishable from retained state; storing one
trait object inside cloned `State` would imply illegal mutable-session cloning;
exposing configured preprocessing would hide a measured cold-path loss behind
the general contract.

## ADR-012 - Keep first-class direct deltas opt-in after the dual-control gate

**Status:** Accepted decision to defer production admission.
**Context:** ADR-011's sound exclusive-transfer direct route removes whole-
snapshot translation and prefix reconstruction, but it also gives up ADR-0199's
serial sibling LCP sharing. A fair decision therefore needs two controls: the
same exclusive-transfer topology to measure entry overhead, and the current
serial-snapshot production policy to measure the replacement users would
actually receive.
**Decision:** Keep `GLAURUNG_AXEYUM_DIRECT_DELTA` strictly opt-in and preserve
serial snapshot as the production default. Accept the first-class contract,
producer, validator, and causal win; reject default admission until direct
sessions gain sound source-identity/COW sibling-prefix sharing or another
bounded topology that clears time and RSS alarms.
**Evidence:** Three clean processes per driver and policy execute 92,721 checks
per artifact with 100% Z3 agreement, zero unknown splits/replay failures,
identical finding hashes, exact traffic, terminal zero cache/session gauges,
and the 4 GiB child limit.

Against topology-equivalent exclusive-transfer snapshot, direct improves
SurfacePen Axeyum time 438.600→390.433 ms (-10.98%), ratio 11.61%, and RSS
0.05%; NETwtw10 improves time 11.148→10.582 s (-5.08%) and ratio 4.84%, with
RSS +1.21%. Z3 drift is +0.71%/-0.25%; every alarm passes.

Against same-current serial snapshot, direct regresses SurfacePen time
362.067→390.433 ms (+7.83%) and ratio 9.54%, while RSS rises 4.88%. NETwtw10
time improves 10.868→10.582 s (-2.64%) and ratio 3.78%, but RSS rises
224,860→262,484 KiB (+16.73%). The production comparator correctly rejects
three alarms. The committed candidate, transfer baseline, and serial baseline
SHA-256 values are respectively
`798c5dd2a6426592c84f255844b1cd7ceaf1d7fc488d3ff18c26d8ee1c832ceb`,
`b7585adf8d4caf62dd2989ac352018bcf64bbf145a7a63affc4bdd9293b55713`, and
`c9502152efa155a8d3f32c8a947ce7e75b45c2538b37d01a4bd95c6c8243ef47`.
**Consequences:** Direct deltas remain an executable causal control and the
right substrate for future P5 work, but no user silently loses serial sharing.
The next direct design must carry prefix identity, not depth alone, preserve
exclusive mutable ownership, and re-run both comparisons. Cold GQ5 and the
accepted serial-snapshot path remain unchanged.
**Alternatives rejected:** enabling direct because it beats equivalent
topology ignores the actual default; retaining serial leases by depth repeats
the measured wrong-verdict bug; accepting NETwtw10 time while waiving its RSS
alarm violates the established production contract.

## ADR-013 - Exact source ancestry for direct serial sibling reuse

**Status:** Accepted as opt-in functionality; production admission pending.
**Context:** ADR-012 identifies serial sibling sharing as the missing direct-
entry topology, but the first attempt proved that retained depth and cloned-
pool `ExprId` values are not source identity. Cloning mutable Axeyum/SAT state
would add a new solver contract and multiply memory. Re-translating complete
snapshots would erase the direct-entry win.
**Decision:** Represent each persistent assertion append as an immutable node
whose parent is the exact prior source prefix. Explorer forks clone the node's
`Arc` in O(1); divergent appends create distinct nodes even when cloned pools
assign the same numeric `ExprId`. A worker-local direct session retains its
active ancestry. Before every check it computes the exact common ancestor by
pointer identity, pops to that depth, and translates only the target suffix.
The caller's confirmed depth remains telemetry/admission input, never identity.
One mutable solver is serially leased; no solver or SAT state is cloned or used
concurrently. Depth/ancestry mismatches and operational errors fail closed.
**Evidence:** The RED test first reproduced the stale equal-depth behavior at
the adapter boundary. The green test starts with source-related siblings whose
second roots require `x=5` and `x=7`, deliberately supplies stale retain depth
two for the right sibling, and proves the session rewinds to the one-root
ancestor, pops once, adds the right root, and returns model `x=7`. All 42
Axeyum-backend tests pass. All 12 explorer tests pass, including a cloned-pool
case where equal numeric expression IDs still produce distinct sibling source
nodes with exactly one shared ancestor. Builds are serialized under 4 GiB.
**Consequences:** Direct mode may safely use the established serial owner lease
again, but remains behind `GLAURUNG_AXEYUM_DIRECT_DELTA=1`. The gate must learn
the direct+serial policy, calibrate its exact traffic from real drivers, and
repeat the ADR-012 production comparison before any default change. Ancestry
nodes are reclaimed by `Arc` lifecycle when no state/session retains them.
**Alternatives rejected:** depth-only reuse is unsound by measurement; hashing
source expressions would make collision handling part of the trust boundary;
numeric `ExprId` equality aliases across independently growing cloned pools;
cloning mutable solver state violates exclusive ownership and worsens RSS;
complete-snapshot LCP reconstructs the work direct entry is intended to remove.

The subsequent gate calibration adds explicit `source-prefix-v1` policy
identity and exact direct+serial traffic for both held-out drivers. One clean-
behavior process each remains 100% agreed with zero unknown/replay failures:
SurfacePen measures 298.6 ms Axeyum / 4,490.9 ms Z3 at 74,384 KiB RSS;
NETwtw10 measures 10.383 s / 52.531 s at 224,712 KiB. These are plumbing and
traffic evidence, not acceptance; three clean processes and both named
comparisons remain mandatory.

## ADR-014 - Accept the source-prefix production win, keep direct opt-in for widening

**Status:** Accepted two-driver evidence; default admission deferred.
**Context:** ADR-013 restores sound direct serial reuse. Production admission
must compare it to the current serial-snapshot default, while a separate
exclusive-direct control isolates sibling topology. New external evidence also
adds much larger `tcpip`/`dxgkrnl` streams that are correctness-clean once but
not yet variance/RSS-gated.
**Decision:** Accept the clean repeated SurfacePen/NETwtw10 production win and
commit its artifact. Keep `GLAURUNG_AXEYUM_DIRECT_DELTA` opt-in until the larger
drivers enter the same fail-closed repeated gate and the exclusive-control
environment drift is resolved. Treat zero-query `win32k`/`pciidex` runs as a
dispatch-recovery coverage question, not solver evidence.
**Evidence:** The source-prefix artifact executes 92,721 checks with exact work,
findings, traffic, replay, lifecycle, and 4 GiB identity. SurfacePen Axeyum
time/ratio/RSS improve 16.11%/17.39%/0.36% against serial snapshot; NETwtw10
improve 6.07%/6.61%/1.72%. Z3 drift is +1.55%/+0.58%, so every production alarm
passes. The artifact SHA-256 is
`ba006d2f8edfdf7754f09702ff172112c5ea3e1134669a7855f5a0a3343660cc`.

A fresh exclusive-direct control shows source-prefix time/RSS improvements of
23.17%/5.33% on SurfacePen and 4.40%/15.81% on NETwtw10, but SurfacePen Z3 drift
is +4.06%. That named comparator remains rejected; no alarm is waived.
**Consequences:** Source ancestry is proven sound and wins the actual current
production comparison, but the default remains unchanged. Add exact repeated
`tcpip`/`dxgkrnl` contracts next, then re-run admission. The comparator now
ignores absolute sample path only while retaining content hash, size, budget,
system, repetitions, work, findings, and every threshold.
**Alternatives rejected:** enabling after only two drivers would ignore the new
51k-query widening signal; counting zero-query drivers would inflate coverage;
waiving Z3 drift would make normalized comparisons non-causal; requiring equal
absolute paths would contradict the byte-identity contract and prevent clean
detached worktrees.

## ADR-015 - Exact shadow unknown-split corpus

**Status:** Accepted diagnostic infrastructure; corpus capture pending.
**Context:** The proposed `tcpip` widening row was measured with a 60-second
per-function ceiling. Raising that ceiling to the lineage gate's 600 seconds
changes both the query set and the validity result: 70,639 queries contain 973
one-backend-only decisions. Zero SAT/UNSAT disagreement does not prove parity
when one solver returns `Unknown` or errors.
**Decision:** Add `GLAURUNG_DUMP_SHADOW_SPLITS` as a combined-shadow-only,
explicit diagnostic. Capture exactly the queries where one backend decides
SAT/UNSAT and the other is `Unknown`/`Error`. Publish content-addressed SMT-LIB
bytes atomically and append only stable backend result classes to
`shadow-splits.tsv`. Never include error strings in identity, count both-
unknown rows as splits, or tax ordinary solving/capture.
**Evidence:** The full source-prefix `tcpip` run has 70,639 same-stream queries,
zero SAT/UNSAT disagreements, 43 Z3 non-decisions, 936 Axeyum non-decisions,
973 unknown splits, 925 warm resets, 480 assertion-cap fallbacks, 1.7x speedup,
and 440,384 KiB RSS. Two focused tests prove the exact one-decided predicate,
stable result classes, atomic exact-byte publication, and TSV row shape under
combined features.
**Consequences:** `tcpip` is not yet a green DriverSpec. Rebuild the release
binary, capture the 60-second split tier, and ingest the formulas into Axeyum's
real-query diagnostic lane. Attribute timeout versus translation/error versus
resource fallback before choosing solver or client work. The larger 600-second
corpus may follow only if its cost is justified.
**Alternatives rejected:** counting unknowns as agreement hides missing
functionality; capturing every query duplicates GQ1 and adds large diagnostic
overhead; storing only hashes is not reproducible; storing error text makes
identity unstable and may expose incidental paths/details.

## ADR-016 - Enforce declared concat operand widths at every solver boundary

**Status:** Accepted correctness fix; repeated widened gate pending.
**Context:** Strict replay of the 60-second `tcpip` shadow-split corpus reduces
733 distinct Axeyum errors to an exact malformed shape. A `setcc` result is a
one-bit expression stored into an eight-bit register slice; `Expr::Concat`
records that low half as eight bits, but the SMT renderer plus both native
solver adapters ignored `hi_w`/`lo_w`. They constructed a 57-bit term while
`ExprPool::width_of` and the concrete domain correctly treated the node as 64
bits. The next extract therefore failed in Axeyum as `extract [63:8] out of
range for width 57`. Z3's later coercion hid the malformed child and also
shifted the high half by one rather than eight bits, changing program meaning.
**Decision:** Keep strict Axeyum sorts. Coerce each concat child to its declared
half-width, by zero-extension or low-bit truncation, in the SMT-LIB renderer,
the Z3 adapter, and the Axeyum adapter before concatenation. This is the
existing `Domain::concat(hi, lo, hi_w, lo_w)` contract and matches the concrete
domain; it is not a solver-specific workaround. Generate Axeyum manifests from
the strict split-corpus index and retain the old bytes as the reproducer.
**Evidence:** The two smallest tcpip error representatives, one Z3-SAT and one
Z3-UNSAT, independently fail Axeyum SMT-LIB ingestion with the same 57-bit
out-of-range diagnostic. Focused renderer, Z3, and native Axeyum regressions
prove that a one-bit low child declared as eight bits becomes a 64-bit concat
with value `0x1201`, and the combined-feature tests pass under the 4 GiB cap.
The archived corpora contain 784 tcpip and four dxgkrnl distinct split formulas
with byte-owning Axeyum manifests.
The exact post-fix reruns then remove every adapter error and warm reset:
`tcpip` falls from 977 to 55 split occurrences (52 distinct: 43 decided only by
Axeyum, nine decided only by Z3) across 72,291 queries, while `dxgkrnl` falls
from six to three occurrences (two distinct, both decided by Axeyum) across
17,712 queries. SAT/UNSAT disagreements remain zero; Axeyum is 1.9x/2.7x faster
in these single processes.
Axeyum's independent cold manifest replay decides all nine Z3-decided residual
tcpip formulas under a 30-second diagnostic cap (1 SAT / 8 UNSAT, 9/9 expected,
no unsupported/errors). SAT search consumes 93.2% of their pipeline time and
total p50/max are 213.7/399.0 ms. Under the production-equivalent 250 ms cap,
5/9 decide and four return explicit `Unknown(Timeout)`, completing the
error-versus-timeout attribution.
**Consequences:** Every old capture containing this shape remains valuable as a
bug reproducer but is not valid post-fix performance evidence. Rebuild and
repeat tcpip/dxgkrnl before admitting either driver to the lineage gate; compare
findings because the old Z3 path used the wrong bit placement. Add no coercion
inside Axeyum IR and do not weaken its error messages.
**Alternatives rejected:** coercing only in the Axeyum adapter would leave Z3,
text capture, and concrete execution semantically inconsistent; teaching
Axeyum to accept mismatched concat sorts would hide a consumer soundness bug;
changing only `setcc` would leave every other declared-width concat exposed.

## ADR-017 - Opt-in synchronized-warm timeout cold retry

**Status:** Deferred; explicit diagnostic remains off by default.
**Context:** ADR-016 removes every widened-driver adapter error. The nine
distinct tcpip formulas where Z3 decides and warm Axeyum does not are all
decided correctly by cold Axeyum under a diagnostic cap. At the production
250 ms cap, cold Axeyum decides 5/9 and explicitly times out on four. A bounded
fresh retry can recover cases where retained SAT state is less favorable, but
it may spend another full per-check budget and must not silently become the
default.
**Decision:** Add `GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY=1` as an opt-in
direct-lineage policy. Retry only when the retained direct session returned
`Unknown` and remained synchronized with the complete assertion snapshot. Use
a fresh ordinary Axeyum solver under the same 250 ms configuration. Return a
recovered SAT/UNSAT result; otherwise preserve the original `Unknown`, including
when the retry errors. Never retry existing one-shot resource fallbacks,
unsynchronized/error sessions, or decided results. Export process counters for
retries, recoveries, repeated unknowns, and hidden retry errors.
**Acceptance gate:** On the exact post-ADR-016 tcpip stream, require zero
SAT/UNSAT disagreements, replay failures, adapter resets, or retry errors;
`retries = recoveries + unknowns + errors`; Axeyum nondecisions must fall; and
the same-stream time/RSS cost must be reported before any default proposal.
Repeat dxgkrnl to prove the no-timeout case is a policy no-op.
**Evidence:** The single-process tcpip candidate executes 71,909 queries with
zero SAT/UNSAT disagreements or retry errors. Its exact counter partition is
15 retries = 4 recovered decisions + 11 repeated unknowns + 0 errors. Axeyum
time rises 128,281.6→131,335.4 ms (+2.38%), but RSS rises
447,888→494,728 KiB (+10.46%), failing the 5% production alarm; 11 Axeyum
nondecisions remain. Query-count drift also prevents treating this as a causal
performance artifact. The candidate therefore fails admission even before
repetition. The dxgkrnl control executes the exact same 17,712 queries and warm
traffic, performs zero retries, keeps zero Axeyum nondecisions/disagreements,
and changes Axeyum time/RSS only 9,190.0→9,220.9 ms / 341,732→341,680 KiB.
**Consequences:** This is a downstream completeness policy, not an Axeyum
solver verdict cache or a relaxation of `Unknown`. It remains off by default.
Profile-v7 records the retained attempt rather than the external retry, so use
the explicit footer counters and unprofiled same-stream timing for this first
candidate; a profile schema revision is required before profiled admission.
Do not repeat this whole-snapshot retry without a topology that avoids its
memory spike or a stricter admission predictor for recoverable formulas.
**Alternatives rejected:** raising every Axeyum timeout changes the common-case
budget; retrying every one-shot timeout simply repeats identical work; using Z3
as an implicit fallback expands the native dependency contract; treating
timeouts as agreement hides incomplete exploration.

## ADR-018 - Opt-in same-session warm timeout continuation

**Status:** Candidate retained; default deferred pending a fixed-work/repeated
gate.
**Context:** ADR-017's fresh cold retry recovers only 4/15 timeout occurrences
and raises RSS 10.46% because it reconstructs the complete snapshot. Axeyum's
incremental BatSat adapter retains the clause database after an interrupted
solve and installs a fresh deadline on each `check`, so one additional call on
the synchronized path may continue useful search without another arena/AIG/CNF
copy.
**Decision:** Add `GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE=1` as an opt-in
direct-lineage policy. When the first retained check returns `Unknown`, issue
exactly one more check on the same solver under a fresh 250 ms deadline before
releasing its worker-local borrow. Reuse already-translated temporary
assumptions; do not duplicate source translation or root accounting. Return a
recovered SAT/UNSAT result; otherwise preserve the original `Unknown`, including
on continuation error. Export continuations/recoveries/unknowns/errors and keep
the cold-retry flag independently off during measurement.
**Acceptance gate:** Require the exact counter partition, zero errors,
SAT/UNSAT disagreements, resets, or replay failures. Tcpip must recover more
than ADR-017's four occurrences without breaching 3% Axeyum time or 5% RSS;
dxgkrnl must perform zero continuations and preserve exact traffic. Any query or
finding drift makes the run functionality evidence only and requires repeated
gate integration before default consideration.
**Consequences:** The switch is explicit/off. A successful single process is
not a default decision; it only selects repeated policy comparison and profile
schema work. A failed result closes blind extra-time retries and redirects the
nine-formula pack to SAT-core attribution/prediction.
**Alternatives rejected:** another fresh solver repeats ADR-017's memory cost;
raising the common timeout taxes every check; unbounded continuation violates
the resource contract; re-translating temporary assumptions would corrupt the
entry-work accounting.

**Evidence:** The 60-second tcpip candidate performs 14 continuations = 6
recoveries + 8 repeated unknowns + 0 errors over 71,842 checks, with zero
SAT/UNSAT disagreements or warm resets. Axeyum nondecisions fall 15→8 while
time rises about 1.1% and RSS falls slightly against the post-fix reference.
The dxgkrnl control performs zero continuations and has zero Axeyum
nondecisions/disagreements, although both wall-time-bounded runs have traffic
drift and therefore are functionality evidence only.

A 600-second tcpip control/candidate pair removes the solver-budget truncation
but still reaches the 400-second analysis deadline. The candidate performs 14
continuations = 5 recoveries + 9 repeated unknowns + 0 errors. Axeyum
nondecisions fall 14→9; Axeyum time rises 204,294.1→208,331.4 ms (+1.98%) and
RSS rises 449,224→449,376 KiB (+0.034%), within the 3%/5% alarms. It executes
70,581 rather than 70,562 queries and reports 782 rather than 780 unique
high-confidence findings. All 780 control findings remain; the two
candidate-only findings are null dereferences in `sub_1c00738a0`. This is
consistent with deadline-limited traversal reaching two additional sinks, but
it is not an exact-output causal comparison. Keep the candidate off by default
until a fixed-work or repeated gate can distinguish policy effect from traversal
timing and require exact findings when the workload is identical.

**Fixed-work follow-up:** `IOCTLANCE_MAX_ANALYZED_FUNCTIONS=N` now stops before
opening reachable function `N+1` and reports `WORK-LIMIT-HIT`. The next tcpip
pair uses `N=156` with a generous wall deadline as a safety backstop. Admission
requires both processes to hit the work limit, not the deadline, and to preserve
exact query traffic and finding hashes before resource deltas are scored.

Both fixed-work processes hit 156/338 functions and never hit the 3,600-second
safety deadline, but the gate still rejects the live comparison. Control runs
70,592 queries with 47 Z3 / 11 Axeyum nondecisions and 782 findings; continuation
runs 70,768 queries with 46 Z3 / 8 Axeyum nondecisions and 783 findings. Their
finding sets have 781 shared rows, one control-only double fetch, and two
candidate-only read/null-deref rows. The candidate's 11 continuations partition
as 3 recoveries + 8 repeated unknowns + 0 errors. Axeyum time changes
133,279.7→135,233.6 ms (+1.47%) and RSS 440,280→441,088 KiB (+0.18%), inside
the alarms, with zero SAT/UNSAT disagreements, resets, or replay failures.

The function boundary removes global deadline drift but cannot remove
authoritative Z3 timeout steering: 47 versus 46 bounded Z3 nondecisions change
the worklist within the identical function prefix. Do not repeat live
exploration as if it were exact. Capture one ordered authoritative query stream
and replay both timeout policies over those exact occurrences; continuation
remains explicit/off until that gate exists.

## ADR-019 - Exact native ordered replay in the production topology

**Status:** Accepted functionality boundary; repeated continuation evidence
pending.
**Context:** The public SMT-LIB ordered consumer fixes occurrence order and
query bytes, but its independent snapshot/lineage policies do not reproduce
Glaurung's source-prefix identity, direct-delta entry, adaptive capacity
fallbacks, or serial sibling leases. Live control/candidate exploration also
cannot hold work fixed because an authoritative Z3 timeout changes the
worklist. Native admission therefore needs a replay boundary that preserves
both exact work and the real production adapter.
**Decision:** Extend ordered trace v1 additively. Each unique assertion gets a
deterministic, topologically ordered native expression-DAG pack bound to its
existing SMT assertion hash. Every check records owner ID, requested retain
depth, persistent/temporary partition, exact source-prefix digest, and whether
the live direct session synchronized. Serial owner share/release events retain
their observation order. The `ordered_native_replay` executable reconstructs
one typed pool, shared immutable source-prefix nodes, and lease lifecycle, then
submits every occurrence through `solve_for_path_delta`. It rejects native/SMT
identity drift, opposite decided verdicts, synchronization drift, operational
resets, cache replay failures, or nonzero terminal owner/session gauges.
Control and one-continuation candidates run in fresh processes and bind the
same trace, finding hash, and independent SMT/model replay artifact.
**Acceptance gate:** The producer validator must accept the complete trace;
the independent Axeyum consumer must replay every query and model read; native
control/candidate repetitions must match event/check/assertion/owner traffic,
source synchronization, findings, and artifact hashes. Require zero opposite
decisions, solver errors, resets, cache replay failures, or terminal gauges,
then apply the existing 3% time, 5% RSS, and variance alarms. `Unknown` remains
a first-class result and is reported rather than scored as a win.
**Evidence:** Native-pack round-trip and malformed-topology tests cover shared
DAGs and all expression variants. Producer tests cover the full owner lease
lifecycle and independently reject a tampered pack. The replay executable
compiles with only `solver-axeyum`; the exact full-driver repetition remains
the next gate.
**Consequences:** The extra native files are restricted Glaurung-local replay
inputs, not a replacement for the public SMT-LIB evidence or a new Axeyum
product dependency. The timeout-continuation switch remains explicit/off until
the repeated native gate passes. A structurally valid trace alone cannot
enable it.
**Alternatives rejected:** reparsing SMT-LIB would bypass the native client
translation; another live pair cannot guarantee exact work; serializing pool
indices without a closed reachable DAG would make packs order- and
allocation-dependent; treating a fallback as synchronized would hide topology
drift.

## ADR-020 - Default bounded continuation inside direct-delta sessions

**Status:** Accepted.
**Context:** ADR-018 retained one same-session check after a warm `Unknown` as
an explicit candidate, and ADR-019 made the real source-prefix/direct-delta/
serial-lease topology exactly replayable. The remaining admission gate required
repeated fixed-work control/candidate processes with independent public replay,
exact finding identity, implementation identity, and the existing correctness,
time, RSS, and variance alarms.
**Decision:** When Glaurung's separately opt-in direct-delta route is active,
enable exactly one same-session continuation after a warm `Unknown` by default.
`GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE=0`, `off`, or `false` remains an explicit
off control; an unrecognized value fails closed to off. Keep fresh cold retry
off and preserve the original `Unknown` after a repeated nondecision or error.
This decision does not default-enable `GLAURUNG_AXEYUM_DIRECT_DELTA` and does not
change one-shot, snapshot, or ordinary Axeyum solver construction.
**Evidence:** Clean Glaurung `33191ac` produced a complete 156/338-function
tcpip run under 4 GiB: 326,364 ordered events, 71,136 checks, 50,687 unique
queries, 10,515 public assertions and native packs, 15,501 owner releases,
7,663 owner shares, 27,940 model reads, 794 finding rows, zero shadow
disagreements, and zero warm resets. The producer validator accepted the exact
artifact. Axeyum `ddb368b7` independently validated all unique queries and
model reads; its report SHA-256 is
`3a9a6b45b2b86148c197b4f20918b65093f249fcbf523a4347d91d63b72b3387`.

Three interleaved fresh-process control/candidate pairs then replayed the same
70,656 synchronized warm checks plus 480 assertion-cap fallbacks through
Glaurung `c1a5635`. Every report matched 13,933 exact reuses, 7,067,382 prefix
assertions, 42,908 additions, 37,436 pops, the complete owner lifecycle, the
finding hash, both source revisions, and replay executable hash. All runs had
zero opposite decisions, synchronization mismatches, errors, resets, cache
replay failures, or terminal paths/owners/references. Candidates performed 29
continuations = 18 recovered decisions + 11 honest `Unknown`s + 0 errors.
Candidate/control Axeyum p50 was 100.166/98.175 seconds (+2.027%); p50 maximum
RSS was 360,484/356,840 KiB (+1.021%); Axeyum timing CV was 0.365%/0.192%.
All are inside the 3% time, 5% RSS, and 3% variance alarms. The fail-closed
comparison artifact SHA-256 is
`0f27afce0b691e977ebf9aa66b67f4bb8744e1c0cc3eb90c2f832b196d1adbc3`.
**Consequences:** Direct-delta users gain bounded decided-rate recovery without
another arena/AIG/CNF copy. Residual timeouts remain first-class `Unknown`s and
the continuation counters remain visible. Preserve explicit on/off controls in
future gates. Direct-delta product admission, wider-driver coverage, and the
zero-query `win32k` frontend gap remain separate work.
**Alternatives rejected:** enabling direct delta from this single-driver replay
would conflate two policies and bypass ADR-0205's wider admission; raising the
common timeout taxes every check; a fresh solver repeats ADR-017's RSS failure;
unbounded or multi-retry continuation violates the measured resource contract.

## ADR-021 - Defer wider direct-delta default after the dxgkrnl no-op gate

**Status:** Deferred.
**Context:** ADR-020 admits bounded continuation only after direct delta is
separately selected. Wider admission needs a no-timeout driver where the enabled
continuation policy is observably inert, exact work and outcomes remain fixed,
and the existing time/RSS/variance alarms still pass.
**Decision:** Keep `GLAURUNG_AXEYUM_DIRECT_DELTA` opt-in. Extend Axeyum's native
comparison tool with a `noop` expectation: the candidate must perform zero
continuations and recoveries, while actual outcomes and complete replay-cache
behavior match within and across policies. Preserve every existing identity,
correctness, terminal, time, RSS, and CV check. Classify `win32k.sys` outside
the current IOCTL frontend; its system-service/callout roots require a separate
sound frontend rather than fabricated IRP dispatch roots.
**Evidence:** Clean Glaurung `9ace064` publishes a complete real
`dxgkrnl.sys` trace with 85,449 events, 4,258 paths, 13,577 unique queries,
3,005 assertions, 17,400 checks, 8,816 model reads, and 312 stable findings.
All 17,400 shadow checks have zero decided disagreement, with four honest Z3
`Unknown`/Axeyum-decided splits; independent Axeyum `1cc19181` replay validates
every query, occurrence, and model read with zero failure. Three ordinary-core
control/candidate pairs preserve exact work, verdicts, cache traffic, owner
lifecycle, and zero continuation traffic. The standard comparison rejects
control/candidate Axeyum-time CV of 14.430%/8.306%, above 3%. A relaxed 20%
comparison is diagnostic only. Slower-core calibration steadies time but moves
one or two control queries across the 250 ms deadline while candidates decide
all four; the no-op gate correctly rejects that semantic/cache drift.
**Consequences:** `dxgkrnl` is green functionality evidence, not admission or a
causal performance win. Repeat the identical, predeclared comparison in a
quieter/exclusive environment or add another valid no-timeout IOCTL driver.
Keep bounded continuation's accepted default inside selected direct sessions,
and keep direct delta itself opt-in.
**Alternatives rejected:** relaxing CV after seeing the samples, selecting only
stable-looking runs, accepting slower-core outcome drift, counting zero-query
`win32k` as solver success, or inventing IRP roots for a different driver
architecture.

## ADR-022 - Add publication-grade paired check measurements

**Status:** Accepted.
**Context:** The pre-submission reviewer audit identifies ratio-of-sums,
single-run timing, mixed decided populations, and unnamed warm fallbacks as
critical blockers. Existing trace v1 timings cannot reconstruct all four
decided/nondecided buckets because they retain only the Z3-authoritative result,
and aggregate fallback counters cannot assign a particular latency to its
execution population.
**Decision:** Extend ordered trace v1 additively under the explicit
`glaurung-ordered-check-measurement-v1` marker. Record both backend result
classes beside their timings and a closed Axeyum execution-class vocabulary.
Keep the authoritative `outcome` field and all native replay fields unchanged.
Historical traces without the marker remain valid for their original replay
purpose but are ineligible for paired publication analysis. Use Axeyum's
fail-closed analyzer over at least five fixed-work repetitions; compare latency
only on occurrences both backends decide in every repetition, use per-
occurrence geomean ratios with deterministic bootstrap confidence intervals,
and report timeout splits and warm/fallback classes separately.
**Evidence:** Focused dual-backend ordered-trace tests publish and validate the
new marker and fields across SAT and UNSAT checks. A negative test recomputes
the event hash after changing an execution class and proves the semantic
validator still rejects it. Direct-delta tests distinguish newly created,
retained, and invalid sessions. The Axeyum analyzer has synthetic five-run
tests for the exact 2x geomean/CI, nondecision buckets, minimum repetitions,
fixed-work drift, execution-population drift, and operational errors.
**Consequences:** Existing engineering admission ratios keep their historical
meaning but are not paper speedups. The next real run must regenerate traces;
old dxgkrnl/tcpip traces cannot be retrofitted because their per-backend result
classes and per-check fallback reasons were never recorded. Warm Z3, neutral-
solver cells, timeout sweeps, and authoritative finding parity remain separate
ADR-0213 gates.
**Alternatives rejected:** infer Axeyum outcomes from timing or aggregate
unknown counters; infer fallback rows from end-of-run totals; silently
reinterpret historical v1; use all observations in the latency ratio even when
one backend did not decide; or publish a ratio of sums with a caveat.

## ADR-023 - Add a topology-equivalent four-cell solver control

**Status:** Accepted.
**Context:** ADR-022 makes the existing cold-Z3/warm-Axeyum population
statistically auditable, but it does not remove the reviewer checklist's most
important baseline objection. A fresh Z3 solver and a retained Axeyum lineage
conflate solver choice with session reuse. Re-labeling the old shadow numbers
would preserve that confound.
**Decision:** Add the off-by-default `GLAURUNG_FAIR_SHADOW` diagnostic. For
every authoritative cold-Z3 query, time four independently named cells in a
deterministically rotating order: Z3 cold, Z3 persistent direct-lineage,
Axeyum cold, and Axeyum persistent direct-lineage. Both warm cells use the same
explorer owner, serial sibling lease, exact source-prefix LCP, one-scope-per-
root push/pop discipline, and temporary-assumption boundary. Z3 implements the
existing `IncrementalSolver` contract with a retained native context/solver;
Axeyum bypasses product admission policy only for this diagnostic and forces
the already checked direct-lineage topology. Cold Z3 remains authoritative, so
all four cells observe one query stream. Rotate cell order by ordered check
occurrence to reduce systematic cache/order bias. Publish the four timings,
outcomes, and both warm execution classes under the additive
`glaurung-ordered-check-measurement-v2` marker; preserve v1 fields as explicit
cold-Z3/warm-Axeyum aliases.
**Evidence:** Real Z3 incremental tests cover push/pop depth, persistent model
lifting, temporary assumptions, and post-assumption restoration. A lineage
test switches between equal-depth cloned sibling pools and proves rewind by
source identity rather than numeric expression ID, then proves a contradictory
temporary assumption does not persist. The ordered-trace validator requires
all four v2 cells, checks their total-time bound, validates closed execution
vocabularies, and checks the legacy aliases. A real DptfDevGen smoke published
227 checks under v2; all four cells decided identically, both warm populations
were 7 created plus 220 retained, no fallback occurred, and the independent
trace validator accepted the artifact. The clean detached `4ae96cf` exercise
then runs five fresh processes with a predeclared 60-second solver bound. Every
run preserves 561 checks; all four cells decide every occurrence; both warm
populations are 7 created plus 554 retained; and no fallback, operational
result, disagreement, or replay failure occurs. Paired geomeans are 0.9661x
[0.8709, 1.0706] cold Z3/Axeyum, 0.7875x [0.6893, 0.8977] warm Z3/Axeyum,
8.9752x [8.5511, 9.4112] Z3 cold/warm, and 7.3157x [6.4477, 8.2741] Axeyum
cold/warm; every per-run CV is below 1.67%.
**Consequences:** The old ADR-022 evidence remains a mechanism/control result,
not a paper speedup. Publication comparisons can now report cold-vs-cold,
warm-vs-warm, and each backend's incremental benefit from the same fixed-work
traces. Four checks consume more of any wall/solver budget than two; production
runs must predeclare a bound large enough to preserve fixed work. This control
does not admit Axeyum direct delta as a product default. A neutral third-party
solver, timeout-sensitive driver, and authoritative finding parity remain open
ADR-0213 gates. The fair warm result favors Z3 on this driver, so the old
cold-Z3/warm-Axeyum headline must be retired rather than presented beside it.
**Alternatives rejected:** compare warm Axeyum only with fresh Z3; infer a warm
Z3 result from cold timing; reuse expression IDs across cloned pools as
lineage identity; let one backend use snapshots while the other consumes
deltas; run the cells in a fixed order; or replace v1 semantics in place.

## ADR-024 - Preserve full-width values in the native Z3 adapter

**Status:** Accepted.
**Context:** The benchmark review exposed a concrete correctness defect in the
consumer adapter: `Expr::Const` and model projection narrowed every value
through `u64`, even though Glaurung's IR supports 128-bit scalar bit-vectors.
Z3 accepted the well-sorted but truncated term, so differential agreement could
silently grade the wrong formula. The fair baseline must not retain that known
oracle defect.
**Decision:** Keep the IR strict and preserve its full scalar width. Construct
bit-vector numerals wider than 64 bits through Z3's decimal numeral API rather
than an integer cast. Lift evaluated models through an exact u128 parser for
Z3 hexadecimal, binary, and indexed decimal numeral forms. Retain the cheap
native `u64` route at widths up to 64 bits. Do not coerce, mask, or downgrade a
malformed value to make the native backend accept it.
**Evidence:** A real W128 regression constrains a symbol to a value with bit
100 and nonzero low bits, then requires the lifted Glaurung model to contain
the exact u128. It fails on the old adapter by returning only the low 64 bits
and passes after the change. The existing Z3, Axeyum, concat-width, direct-
delta, timeout, and ordered-trace suites remain green.
**Consequences:** Z3 can again serve as an adapter oracle for Glaurung's full
scalar width range, subject to the rest of the stated TCB. Historical
primitive results containing the truncation are stale and must be regenerated;
they are evidence that strict typing found a consumer bug, not evidence of a
Z3-core failure.
**Alternatives rejected:** scope all comparisons to at most 64 bits while
leaving the defect; truncate both backends for apparent parity; represent a
128-bit scalar as two unrelated symbols; or classify the wrong UNSAT as a Z3
solver bug.

## ADR-025 - Make the production Axeyum backend QF_BV-profile explicit

**Status:** Accepted.
**Context:** The artifact review found that Glaurung's `solver-axeyum` feature
implicitly selected Axeyum's former full default, even though the production
native translator uses only the scalar QF_BV API. The same module also retained
the P1 SMT-LIB text bridge, whose `solve_smtlib` calls genuinely require the
full parser and multi-theory facade. Treating both paths as one feature made the
minimal-footprint claim false and made a direct switch to `qfbv` fail to
compile.
**Decision:** Consume `axeyum-solver` with defaults disabled and exactly the
`qfbv` feature under `solver-axeyum`. Move the reference-only text bridge behind
an additive `solver-axeyum-text` feature that explicitly enables
`axeyum-solver/full`. Compile its imports, implementation, and tests only under
that feature. Keep the native translator, warm engine, model replay, proof
export, and production selection policy unchanged.
**Evidence:** Before the split, `cargo check --features
solver-z3,solver-axeyum` failed because `solve_smtlib` and
`solve_smtlib_get_value` are absent from the QF_BV profile. After the split the
same production-profile check passes, and `cargo tree --features
solver-axeyum -e features` contains only `axeyum-solver feature "qfbv"`; no
full-only Axeyum crate is active. `cargo check --features solver-axeyum-text`
separately proves that the legacy bridge remains buildable.
**Consequences:** The wheel-facing direct backend now realizes the claimed
minimal solver surface rather than relying on a default-feature accident. The
text bridge stays available for reference tests but is visibly a full-profile
tool and cannot silently bloat production builds. This changes neither solver
authority nor benchmark semantics.
**Alternatives rejected:** delete the useful reference bridge; expand `qfbv` to
include the whole SMT-LIB/multi-theory facade; duplicate a parser in Glaurung;
or describe the dependency as minimal while continuing to activate `full`.

## ADR-026 - Make concretization a first-class policy

**Status:** Accepted.
**Context:** The accepted authority experiments show that arbitrary, least,
greatest, and two site-hash choices are settings of one model-value knob, not
separate solver algorithms. They were nevertheless implemented as an enum and
environment parser embedded in `explore.rs`, duplicating selection logic at
`concretize_addr` and `eval_concrete`. The publication plan requires a measured
policy sweep, while symbolic memory must remain a separate architecture item.
**Decision:** Extract a public, `Send + Sync` `ConcretizationPolicy` contract.
Give each request only a stable seam, semantic purpose, and instruction address.
Keep checked solving, model evaluation, address binding, and ordered tracing in
the explorer. Route both value-selection seams through injectable policy-aware
helpers. Make `GLAURUNG_CONCRETIZATION_POLICY` the preferred built-in selector,
retain `GLAURUNG_CANONICAL_MODEL_CHOICE` exactly for preregistered campaigns,
and reject simultaneous use. Preserve every existing policy ID and both legacy
AnyModel trace IDs. Represent `BoundarySet` and `Defer` in the contract, but
fail closed until A3 state forking and A2 symbolic memory actually implement
their distinct semantics.
**Evidence:** The TDD red gate failed on the absent policy types and resolver,
then six contract tests passed for the AnyModel default and trace IDs, every new
and legacy alias, precise invalid/conflicting config errors, complementary
site-hash decisions, and custom set/defer policy values. Seventeen focused
explorer tests pass, including explicit least/greatest injection at both seams,
path binding versus read-only evaluation, infeasible-path handling, unsupported
widths, and all prior extrema. On the exact tcpip 15-of-338 boundary, two clean
A0 Axeyum runs reproduce the three accepted pre-A0 runs: 126 findings, ordered
hash `a67d7bca28602ab20bbc46d9a5d42705463bd340067dc8e6ec660b35d58ba265`,
2,991 solves, and identical AnyModel counters. The expected two Z3-only rows
remain. A separate one-function gate proves preferred and legacy minimum config
produce identical output and work: 13 completed choices, 858 probes, 869 solves,
and zero failure partition.
**Consequences:** A0 is behavior-preserving enabling infrastructure. The next
coverage work is a preregistered sweep over policy configurations. A3 must add
bounded set forking before `BoundarySet` becomes production-selectable. A2 must
change the memory model and starts only if the cheap sweep leaves measured
coverage headroom. Existing experiment scripts can migrate to the preferred
variable without invalidating archived commands.
**Alternatives rejected:** keep adding one-off enum branches in the explorer;
rename the legacy variable without compatibility; collapse a boundary set to
its first value; treat deferred symbolic memory as another scalar policy;
change default traces while claiming byte-for-byte reproduction.

## ADR-027 - Preserve taint provenance before scoring policy coverage

**Status:** Accepted.
**Context:** The first-15 tcpip AnyModel authority control has two stable Z3-only
double-fetch rows, and the four-schedule experiments used raw sink-set growth as
a bounded coverage observation. Exact trace inspection showed both rows occur
inside `TcpSendTrackerMarkTransmits` and depend only on generic `Arg0` ancestry
plus fresh values loaded through it. The explorer nevertheless relabeled every
uninitialized load through any tainted address as `*attacker`, bypassing the
normal high-confidence rejection of `ArgN` pointer noise.
**Decision:** Store every stable source label on a tainted symbol and propagate
an uninitialized load by prefixing each exact address source. Never replace
specific provenance with generic `*attacker`. Keep raw diagnostics available,
but score future concretization-policy coverage on a preregistered nonzero
labeled-positive population while reporting raw, confidence-gated, and
validated partitions separately.
**Evidence:** The red regression expected an uninitialized mixed-source load to
retain `*Arg0` and `*SystemBuffer` but observed only `*attacker`; it passes after
the correction, together with all 18 explorer tests. Both sole-authority
release builds complete two clean repetitions on the exact 15-of-338 tcpip
boundary. AnyModel remains deterministically 128 Z3 versus 126 Axeyum raw rows,
with the two differences relabeled `**Arg0`; least unsigned remains exactly
110/110. Normal confidence-gated execution reports zero findings for both
authorities, and every least-unsigned raw row carries only `Arg0`, `Arg1`, or a
dereference thereof. PDB symbols map the sites to the 2,104-byte internal
`TcpSendTrackerMarkTransmits` function; disassembly shows tree-node field reads
at offsets `-0xc` and `+0x8`.
**Consequences:** ADR-026's A0 abstraction remains accepted. The older raw
authority artifacts remain deterministic exploration evidence, but their
interpretation as a true-positive coverage frontier is superseded. Do not
select BoundarySet, DiverseEnum, or symbolic memory to recover these two rows
or maximize the arbitrary-model raw union. First select and label a corpus with
nonzero accepted findings; begin symbolic memory only if the corrected cheap
policy sweep leaves validated recall headroom.
**Alternatives rejected:** suppress the two addresses by special case; keep
`*attacker` and document the false positives; treat every `ArgN` dereference as
attacker-controlled; discard raw output; or call least-unsigned preservation
because its two authorities emit the same zero-confidence diagnostic set.
