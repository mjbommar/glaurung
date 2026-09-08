# Decompiler Review Implementation Plan

> **Kind:** record · **Date:** 2026-09-02

Status: detailed execution specification subordinate to the canonical roadmap

Created: 2026-09-02

Review basis: `README.md` and `01` through `06` in this directory

Scope: local Glaurung implementation, tests, measurements, and documentation

Current-state snapshot: reconciled 2026-09-06 through homogeneous-float
behavioral commits `db750dbc`, `197e6383`, and `64181d02`, baseline commit
`1bee3fb1`, and census commit `a0915220`. WP0 and
WP2 and WP7A are complete; the bounded WP1 production trial is complete and rejected,
with selective substrate cleanup still open under WP10. WP4 now has a pinned
715-function structural comparison and a 334-candidate execution comparison
with zero unexplained structural regressions, zero execution regressions, and
nested post-tested branches preserved; it still lacks the remaining promotion
measurements. WP5, WP8, WP9, and WP10 have production or shadow vertical slices
but have not met their full exit criteria. WP6 has its first per-use signedness
slice and the O0 `classify` signed-result vertical slice, but not the general
solver. Its latest bounded edge at `8ab39b50` preserves an authoritative
unsigned parameter declaration while rendering a contradictory signed machine
comparison at the exact use; fixture-215 Clang O2 is now five-for-five. WP3 and
the general WP7B idiom framework remain the principal architectural packages.
WP3 has its first bounded consumer migration at `925dc002`: pipeline-owned SSA
now has explicit conservative invalidation and reconstructs after the
definedness pass changes uses. Commit `09522773` retains that owner across
return materialization, and `f05c9a5d` carries an opaque value-identity sidecar
through AST lowering and migrates exact float-role projection away from
display-name parsing. Commit `af65c260` migrates optimized DWARF register-local
recovery as the second product consumer. Commit `7bea3314` defines canonical
instruction-origin sets and `59840017` gives statements a transparent carrier
without changing the 419-pair output map. Commit `8cb7d171` then makes the
enabled AST transformation and structured return-width consumers transparent
to that carrier. Its release-built stripped differential moves from 112 to 103
regressions while retaining 17 improvements, with zero changed classifications
and zero infrastructure problems; see
`results/wp3-statement-origin-propagation.md`. Commit `cda7ab73` migrates the
post-pipeline C++ exception consumer and unions the contributing instruction
origins into recovered `try`/`catch`, `throw`, and catch-return nodes. The real
Clang O2 stripped exception cell returns to green and the same complete
differential improves again to 102 regressions, still with 17 improvements and
zero infrastructure problems; see
`results/wp3-exception-origin-propagation.md`. Commit `cb9e5b10` then migrates
six control-oriented wildcard consumers with an exactly neutral complete
differential; see `results/wp3-control-consumer-origins.md`. Commit `52914784`
migrates guarded-switch recovery without weakening its ownership and range
proofs, remains exactly neutral on the same differential, and reduces the
shared whole-Python failing-node set from 228 to 227; see
`results/wp3-guarded-switch-origins.md`. Commit `f7b47953` migrates every
guard-chain rewrite, keeps the complete
stripped differential exactly neutral, and leaves no guard-chain node in the
224-entry shared Python failure cache; see
`results/wp3-guard-chain-origins.md`. Commit `3b7d8a95` then migrates
comparison-tree and linear-labelled
switch ladders plus final join-to-`break` cleanup with an exactly neutral
stripped differential; see `results/wp3-switch-ladder-origins.md`. Commit
`a807b2d0` completes the next bounded wildcard migration in
`latch_predicate`: attributed predicate, snapshot, entry-copy, and loop-update
statements remain visible, and every removed contributor is unioned into the
surviving loop. Its complete stripped differential is again exactly neutral;
see `results/wp3-latch-predicate-origins.md`. The post-migration audit confirms
that `aapcs64_indirect_result.rs` is the next enabled raw-statement consumer to
migrate before expression ownership. Commit `c51a116d` closes that omission
for AAPCS64 `x8` and SysV hidden-result setup, nested traversal, stack
adjustments, and post-promotion call binding. Its complete stripped
differential and 221-node whole-Python failure set are exactly neutral; see
`results/wp3-indirect-result-origins.md`. Commit `02b0da5c` then migrates
`vector_copy`: attributed and nested lane transports rejoin without losing
their owners, synthesized wide operations receive exact consumed-origin
unions, and multiple nested consumers still fail closed. Its complete stripped
differential and normalized 221-node whole-Python failure set are exactly
neutral; the current undeclared-local invariant is eight-for-eight green. See
`results/wp3-vector-copy-origins.md`. The next confirmed wildcard omission is
the raw guarded-return and diamond surface in `select_fold`. Commit `e92d7248`
closes that surface, including nested `try`/`catch` traversal, and improves the
whole-Python boundary from 221 to 218 failures with zero new nodes. A controlled
parent/tip release A/B proves all three removals, including corrected ARM
hard-float execution. See `results/wp3-select-fold-origins.md`. Commit
`18ef9fdc` restores GOT-pointer folding through origin carriers and closes its
exception, transfer, push, and call-expression omissions with exactly neutral
stripped and whole-Python comparisons; see
`results/wp3-got-fold-origins.md`. Commit `217796be` then makes attributed
definitions and exception paths participate in relocation-proven
function-table recovery and conservative clobber tracking. Its stripped map is
exactly neutral, while the whole-Python boundary improves from 218 to 217
failures with no addition; a controlled release A/B proves the recovered
portable `ops[5]` table is attributable. See
`results/wp3-function-table-origins.md`. Commit `849c5a5b` then migrates direct,
resolved GOT-indirect, and relocation-proven vtable tail-call recovery. Its
stripped map is exactly neutral and its whole-Python boundary improves from 217
to 216 failures with no addition; a controlled release A/B attributes the
recovered Rust trait-object tail to this commit. See
`results/wp3-tail-call-origins.md`. Continue through the convention-generic
argument-layout folds in `call_args.rs`, then the architecture-specific
`cdecl32.rs` and `aapcs.rs` setup/removal paths, before beginning expression
ownership. Commits `b6172031` and `a0917da5` complete that generic-layout
slice: attributed setup is consumed with exact call-owner unions, while an
explicit purity boundary leaves ARM frame loads rooted for the general scan.
The release-built whole-Python boundary improves from 216 to 215 failures with
zero additions, and the real mixed hard-float call retains
`arm_hf_mixed_callee(7, measured, negate)`; see
`results/wp3-recovered-call-layout-origins.md`. Continue with `cdecl32.rs` and
`aapcs.rs`. Commit `c291328a` completes the cdecl32 slice: attributed outgoing
stores, lowered pushes, cleanup evidence, and rebasing remain visible; removed
setup owners join the call and decrement owners survive on the net stack
adjustment. A release A/B proves real `helper3(a, b, c)` recovery and two
whole-Python failures removed with zero additions; see
`results/wp3-cdecl-call-origins.md`. Commit `e403de27` completes the AAPCS
slice: attributed locked contracts,
pure-VFP setup, outgoing stack areas, and phase-sensitive stack adjustments
remain visible, and removed VFP setup owners join the call. Release A/B proves
two ARM32 execution failures removed and one stripped fixture improvement with
no added regression; see `results/wp3-aapcs-call-origins.md`. The generic,
cdecl32, and AAPCS call-argument surfaces are now migrated. The enabled
consumer re-audit selected `src/ir/canary.rs`; commit `9942f948` makes its save,
reload, branch, failure-call, and nested structured paths origin-transparent
and unions every removed owner into the synthesized canary comment. The
  complete stripped differential and exact 211-node whole-Python failure set are
  neutral, and the release declaration invariant is eight-for-eight green; see
  `results/wp3-canary-origins.md`. Commit `8989cecc` then makes integer-pair
  return composition origin-transparent and rejects contradictory explicit SSE
  low-result evidence; its stripped map and normalized 211-node semantic
  whole-Python boundary are neutral. Commit `82a95253` batches the next five
  related call-analysis surfaces: register discovery, result attribution,
  frame-load alias barriers, enclosing reaching definitions, SysV SSE-pair
  forwarding, and format-proven variadic arity all see through statement
  carriers. All six focused tests failed before their fixes, and the complete
  109-test call-argument module is green. The whole-Python boundary improves
  from 211 to 209 exact failure nodes with no addition; focused release A/B
  attributes both restored indirect-tail/table-dispatch tests to this batch.
  Commit `b84c03e5` completes the following enabled-consumer slice in
  `src/ir/lazy_call_select.rs`: result inventory, recursive traversal,
  adjacent folding, goto census, every supported diamond matcher, and
  replacement construction now see attributed statements in both production
  entry points and union every consumed owner. Five focused tests were
  observed red; the module, origin, release real-binary, fixture-189, and
  complete Rust gates pass. The whole-Python gate has zero attributable
  failure-set change; its one newly exercised i386 invariant reproduces at the
  parent.
  Most
semantic consumers, multi-output definition identity, expression origins, and
structured line mappings remain open. A bounded, pre-WP3 WP7B relational slice
is landed and proved at `9c9c607c`; it does not establish the general
framework.
The first WP2 request-model slice is landed at `d6a65779`. Module-level and
reusable-session `decompile_at` now construct one pipeline-owned
  `DecompileRequest`, `AnalysisBudget`, and `RenderOptions`; every discovery
limit survives one checked conversion. Exact-range discovery converged with
the other entry points at `5a2d6c86`, and `e19bd73b` moves the ordered helper,
ABI-call, recovered-callee, and caller-effect sequence behind one
`callee_contracts.rs` boundary used by all four entry points. The other three
public entry points still need to construct the request directly; the common
per-function orchestrator is now shared from prepared LLIR through AST passes
at `41bd90a6`, but discovery/context assembly and rendering remain adapter-owned.
`5ea45dca` adds the result half for the single-function path with real health,
completeness, provenance, and a versioned budget/pass fingerprint. `15d044eb`
makes range, all, and many construct the same typed request and result internally
before preserving their legacy Python return shapes. `e0588083` moves the
image-wide string/data reconciliation, relocated read-only data, function-table,
and GOT facts into one pipeline-owned `ProgramRenderContext` used by all four
adapters and prepared once per batch. `21f8b29a` similarly makes one
`ProgramDebugContext` own DWARF/PDB declaration and type preparation for every
adapter. `2ef9c4eb` makes `ProgramNameContext` the sole owner of the combined
object parse plus discovered, FLIRT, and referenced-function name enrichment.
`d900cf1b` makes one `ProgramDiscovery` carry the exact converted budgets and
their discovered functions for all four adapters; exact-range discovery now
also releases the GIL. `1e1ac0a8` moves post-lowering semantic finalization --
analyst and DWARF local facts, exception recovery, machine-frame cleanup, and
PDB field annotations -- behind one `finalize_prepared_ast` boundary used by
all four adapters. `2f7a6149` then makes one `render_prepared_ast` select
declaration authority, project types, record conflicts, render every style,
and attach per-function incompleteness for all four adapters. `2ee8fa15` moves
the remaining lift, direct-callee-fact, analyst-name, typed/shadow LLIR,
stack-hint, lowering, finalization, and rendering sequence into one
pipeline-owned `decompile_function`; all four public adapters now call that
single per-function transaction. `74853fcc` adds checked coarse semantic-stage
transitions and a focused invalid-order failure; `4ea067df` registers and checks
the canonical order of all 20 production AST passes, including safe optional
omissions and typed rejection of unknown, repeated, or backward passes.
`5f7df194` replaces both hand-written AST settle loops with one bounded
fixpoint driver and emits their rounds, firing counts, and quiescent/bound-
reached termination through the pipeline profile. Remaining budget classes and
their closure tests remain open, so WP2 is
substantially underway rather than complete. See
`results/wp2-pipeline-request-model.md`.
The bounded WP6/WP9 AAPCS32 follow-on is landed at `62a4ab72`. An
authoritatively declared eight-byte integer parameter now carries both aligned
entry words into the AST instead of presenting its high word as an invented
local. Four ARMv7/ARMv7-A32 O2 fixture-215 cells move to execution-correct
output with no attributable regression across the 60-cell architecture slice.
Big-endian ordering, inferred prototypes, and residual A32 O0 storage defects
remain deliberately open. See
`results/wp6-wp9-aapcs32-wide-parameters.md`.
The matching i386 cdecl32 carrier is landed at `fcd9bd2d`, with baseline and
census commits `9b307e0b` and `d1bf72a7`. Authoritatively declared eight-byte
integer parameters now join their two adjacent incoming stack words without
truncating the promoted whole-argument role. Fixture 202 and 215 gain nine
execution-correct O0/O2 cells with no attributable regression in the complete
410-lane i386 comparison. Signed selectors remain WP6/WP7 work and the i386 O2
mixed selector remains WP5 work. See
`results/wp6-wp9-cdecl32-wide-parameters.md`.
The required exact-clean-checkout Rust gate at `d1bf72a7` is green: the library
target reports 4,126 passed, zero failed, and five ignored, and every
integration and documentation target passes. The long identity-retrieval
target independently reports 44 passed, zero failed, and ten ignored.
The next bounded WP7 range slice is landed at `f39bdf0e`, with census commit
`98ea766c`. The i386 O2 `wide_selector_mixed` guard now recovers `op <= 5` from
the exact cdecl32 high/low borrow identity and removes the repeated impossible
`op > 5` nested arm. The complete 410-lane i386 sweep has no attributable
execution-verdict movement; this is an output/readability improvement, and the
still-unrecovered indirect jump remains WP5 work. See
`results/wp7-cdecl32-wide-range-predicate.md`.
The required exact-clean-checkout Rust gate at `98ea766c` is green: its library
target reports 4,132 passed, zero failed, and five ignored, and every
integration and documentation target passes. The complete host sweep executes
824 of 838 lanes with zero regressions and reproduces 35 pre-existing
unratcheted improvements.
The first fixture-217 follow-on is a bounded WP9 instruction-semantics
increment: legacy `ADDPS`, `SUBPS`, `MULPS`, and `DIVPS` now preserve four
typed binary32 lanes. The following WP6/WP9 call-boundary increment is also
landed. It gives `__mulsc3` and `__muldc3` exact source-ordered
`xmm0`..`xmm3` inputs and keeps their two distinct result contracts honest:
`__mulsc3` returns two binary32 lanes packed into `xmm0`, while `__muldc3`
returns one binary64 component in each of `xmm0:xmm1`. GCC and Clang O2
`complex_float_multiply` and `complex_multiply` now pass, four fixture
improvements with no regression in the scoped adjacent controls. This is a
bounded SysV compiler-runtime contract, not completion of the general call or
constraint model. See `results/wp9-packed-float-arithmetic.md` and
`results/wp6-compiler-complex-helper-boundary.md`.
The full Rust gate is green at `41af392d`: its library target reports 4,065
passed, 0 failed, and 5 ignored, and every integration and documentation target
also passed. Its required whole Python gate completed red: 4,613 passed, 116
failed, 68 skipped, 896 xfailed, and 125 deselected in 2,493.96 seconds. That
run exposed the expected stale two-test census and improvement ratchets as well
as the repository's broad pre-existing failures; the census is refreshed in
the accompanying documentation commit, while behavioral baselines are not
blindly rewritten. This is not a current-tip green `release` claim. M3 through
M6 remain open.

The latest bounded WP5 slice carries that exact seven-case evidence through
the production structurer. Clang O2 fixture 204 now renders cases `0..6` plus
the out-of-table default with no indirect-jump placeholder and passes all 34
deterministic execution cases. Production accepts that dense shape only when
SSA proves that the guard condition transitively consumes an unsigned
comparison; this excludes lookalike conditionals that lack range-proof
semantics. All 20 fixture-204 cells and the 55 production-structurer tests
pass. The required full Rust gate is green at this increment's exact source:
its library target reports 4,091 passed, 0 failed, and 5 ignored, and every
integration and documentation target also passed. The complete 838-lane
harness emits 2,950 pass, 378 known fail, 121
structural, zero missing, zero no-case, and zero infrastructure lanes. Its
baseline-aware comparison reports 34 older unrecorded improvements and one
`rust_slice_get` regression; an isolated clean-`55ab688b` A/B reproduces that
failure with identical output, proving it predates this increment. The fixture
204 improvement is recorded by changing this cell's baseline from `fail` to
`pass`. See `results/wp5-production-dense-guarded-switch.md`; the
earlier shadow-only boundary in `results/wp5-chained-strict-guard.md` is now
superseded for this cell. WP5 is not complete: the real fixture's remaining
duplicate-owner diagnostic is now closed. `Region::Borrowed` distinguishes a
predecessor-specific rendered return tail from its single structural owner;
both `EdgeUnaccounted` and `BlockDuplicated` are absent for the cell while its
execution-correct output remains unchanged. A rejected plain-`Goto` prototype
exposed a real `152_deep_nesting` return-value regression; the typed borrowed
form preserves that canary, and the complete 838-lane rerun has no regression
attributable to the repair.
The post-commit whole Python gate remains red at 4,612 passed and 128 failed;
it is recorded in the result rather than promoted to a release claim. Its
fixture-204 strict-xfail findings were stale. The independently reproduced
inventory refresh reduces the deduplicated structural count from 473 to 472
and unrecovered functions from 27 to 25. Deduplicated emitted gotos move from
4,652 to 4,655 because one older stale row now records nine more gotos; the
focused inventory suite passes. An isolated parent/tip fitness A/B records
the final borrowed-provenance slice's exact cost as 61 product lines with no file
threshold crossing, maximum-size growth, or IR-count growth. The next WP5
slice is now landed at `9ad9414d`: `Cfg` builds one immutable, ordered
case/default/provenance object from typed edges and labels, and both production
and shadow-v2 consume it. Completeness fails closed when any typed case lacks a
non-empty label, when default evidence is ambiguous, or when evidence is
otherwise truncated. The independent v2 verifier checks relational invariants
rather than trusting or duplicating the producer. Forged missing-label,
missing-default, and incomplete-evidence tests prove those refusal boundaries.
The full Rust gate reports 4,351 passed, zero failed, and 17 ignored across 35
targets. See `results/wp5-shared-switch-evidence.md`. This completes the shared
transport increment, not WP5: remaining compiler/architecture execution cells,
decline classification, and the full Python/matrix gates remain open.
Commit `460259fa` carries that canonical object through a WP4 `RawLoop`, closing
another place where lowering reconstructed switch facts from successor order.
The real fixture-206 A32 loop now retains its proven guard-only default even
though that target is not a dispatch successor, and its native v1 round trip
remains green. Incomplete evidence declines to the prior lossless labelled
form. This is prerequisite transport for handler partitioning, not the
partition itself; labelled handler bodies and their shared join remain open.
See `results/wp5-raw-loop-switch-evidence.md`.
Commit `88e6584c` then uses that transport to absorb the real raw-loop range
guard under the same complete-evidence, single-predecessor, and SSA unsigned
comparison proof as ordinary guarded switches. Fixture 206 now renders
`switch ((var11 & 7))` directly: the `var12` temporary, redundant range-check
`if`, and one goto disappear while the typed default and native execution are
preserved. See `results/wp4-raw-switch-guard.md`. Handler bodies remain labelled
until the separate exclusive-entry/shared-join partition is proved.
The first such partition is now production at `13588284`. A case/default entry
whose only predecessors are its typed dispatch/folded guard is emitted directly
inside that arm, while every shared successor remains in canonical raw
ownership and is emitted once. The real A32 loop moves from seven remaining
gotos to zero with unchanged native execution and silent accounting. This is a
one-block exclusive-prefix proof; see
`results/wp4-raw-switch-exclusive-entries.md`.
Commit `ca30c62f` extends that ownership through bounded, disjoint private
linear prefixes and independently rejects a forged prefix that crosses a
shared join. The exact-tip structural gate completes 25 of 27 tests: its eight
regression findings and six improvement findings all reproduce byte-identically
at the preceding exact commit. They are baseline debt and earlier improvements,
respectively, rather than changes attributable to this increment. The complete
six-test def-use census likewise produces an identical parent/tip report (four
tests green, the same regression and improvement ratchets red). Branching
private regions are now covered by the follow-on `1ce1a80b`: bounded,
predecessor-closed private DAGs retain their conditional inside the typed arm,
while an independent verifier rejects a forged shared-join crossing. A real
GCC ARMv7 A32 case loses two out-of-line gotos, preserves native execution, and
keeps accounting silent. Cyclic, cross-arm, and shared-join ownership and the
remaining promotion gates stay open; see
`results/wp4-raw-switch-private-prefixes.md` and
`results/wp4-raw-switch-private-branches.md`.
The refresh also caught and rejected a local `weak_fold` readability regression
before baseline acceptance. Guard-only return-value prefixes retain ownership
while only their shared terminal is borrowed; `weak_fold` is back to two gotos,
fixture 204 remains account-clean, and the `deep152_while_tower` correctness
canary remains green.
The next architecture slice is now landed separately at behavioral commit
`310b949e`: GCC AArch64 O2's guarded `LDRB`/`SXTB #2` compact byte table
becomes an execution-correct 16-case production switch for
`206::dense_dispatch`. The exact fixture moves from `fail` to `pass`; a
ten-lane adjacent AArch64 switch slice has no regressions, and the full Rust
gate is green. An isolated full 412-lane AArch64 parent/tip comparison produces
the same four older regressions and fourteen stale improvements at both
revisions, proving no architecture-wide regression is attributable to the
slice. This is one fail-closed compiler encoding, not completion of WP5's
architecture matrix. See
`results/wp5-aarch64-compact-byte-switch.md`.
Hardening commit `5dbc3fc4` additionally invalidates all AArch64 dispatch facts
across direct and indirect calls, preventing a callee-clobbered address from
being reused as false switch evidence; the focused and architecture-wide
results are unchanged. Its post-source whole Python gate completed red at
4,595 passed and 126 failed. Exact comparison with the 118-failure parent
snapshot found eight tip-only node IDs: seven pass together on immediate
clean-tip retry, while the sole deterministic delta is the six-test census
increase committed at `88bb8650`. The focused census suite is green and the
never-executed pool remains zero; this is triaged full-gate evidence, not a
release-green claim.
The following i386 slice is landed at behavioral commit `b84233ec`. GCC PIC's
PC thunk and checked GOT arithmetic now preserve distinct table and target-base
addresses through bounded relative decode. Eight i386 O2 cells move from
`fail` to execution-verified `pass`, including a switch nested in a loop. The
complete 410-lane parent/tip comparison has zero attributable regression and
the full Rust gate is green. The census increase is recorded at `86d224f5`;
its exact-checkout whole Python gate completed at 4,597 passed, 125 failed, 891
expected failures, 78 skipped, and 125 deselected. There are no tip-only
failing node IDs relative to the AArch64 parent; the sole removed failure is
the census check updated by `86d224f5`. This is triaged broadly-red evidence,
not a release-green claim. See
`results/wp5-i386-got-relative-switch.md`.
The following ARMv7 A32 slice is landed at `76cce5d1` and hardened at
`5ef0bcb9`. Exact PC-relative literal materialisation, unsigned byte-table
decode, and `add pc, pc, rOffset, lsl #2` semantics recover nine O2 switch
functions with zero parent/tip decline across 410 lanes and 1,604 function
verdicts. Production `dense_dispatch` and shadow-v2 `dispatch_in_loop` pass
native execution. Commit `6f0ba701` closes the latter's production-v1 WP4
ownership defect: all six latch backedges are locally owned and production now
passes with a real switch inside the loop. Four valid wide byte switches in
`43_base64` exposed a v1 recursive
stack overflow; the shared graph-sized structure work budget now selects the
complete labelled CFG in 0.17 seconds instead of crashing. See
`results/wp5-armv7-a32-byte-switch.md`.
The exact 410-lane post-repair comparison has one attributable movement,
`dispatch_in_loop` from `fail` to `pass`; two unrelated alternating rows are
recorded as same-revision harness instability rather than code regressions.
See `results/wp4-a32-multi-latch-dispatch-loop.md`.
The follow-on quality increments at `28b3bc5b` and `0e29ffc4` eliminate the
unreachable undefined `var1` select arm and the final outer-guard
`EdgeViaGoto`. Exact host and A32 comparisons show no attributable status
decline; see `results/wp4-a32-guard-quality.md`.
Commit `c9483542` then lowers every exact raw-loop header backedge to
source-level `continue`, removing six more gotos and the unused header label
from the real output without changing its execution status or clean accounting.
The exact 3,346-function host comparison has zero status/category movement;
see `results/wp4-raw-loop-continue.md`.
The next host-wide-selector slice is landed at `9333881e` and hardened at
`98a0d2d3`. Clang and GCC O2 fixture-215 `wide_selector_mixed` now retain all
six typed cases even though case zero borrows a return also reached by the
formal default. The first complete def-use run caught that unrestricted SSA
ancestry and cyclic borrowed-return reachability regressed the already-green
fixture-206 Clang O2 loop switch. That movement was rejected, reduced to a
unit and real-binary regression, and repaired by distinguishing boolean
predicate provenance from arbitrary data dependence and by keeping cyclic
guard ownership on a direct-comparison contract. The hardened result preserves
both switches and restores all 169 normalized def-use findings byte-for-byte.
The exact whole-Python comparison has no ordinary tip-only regression, and the
1,676-object inventory moves from 38 to 30 unrecovered observations and from
6,823 to 6,502 emitted gotos. Commit `0466a2e0` ratchets those repairs and
promotes the Duff latch to a positive test; see
`results/wp5-wide-selector-shared-return.md`.

Commit `a8ba1b87`, hardened at `dcdc99cc`, closes one concrete WP3/WP9 identity seam exposed by the
whole-Python fail-fast gate. Target-aware SSA already gave ARM32 `fp` and
`r11` one canonical value, but value numbering applied that canonical base
only to uses. Definitions now adopt that target-qualified base only for ARM32
calling conventions and only when the architecture-blind compatibility parent
cannot express it; the earlier all-target definition rewrite was rejected.
The real GCC A32 O0 `03_loop_shapes::while_prefix` output moves from
an undefined raw `var0` frame base back to source-level `p[i]`, initialized
`i`/`s`, and execution-correct output. All 44 value-numbering, 12 SSA, 85
stack-local, and 12 ARM32 semantic tests pass. The complete Rust gate is green
with 4,200 library tests passed, zero failed, and five ignored. The complete
def-use module is 4/6 green; both red ratchets reproduce at the pre-repair
parent and therefore remain separately tracked baseline debt. This is a bounded identity
handoff, not completion of WP3 invalidation/origins or the wider WP9
architecture migration. See
`results/wp3-wp9-arm32-definition-identity.md`.

The adjacent `4fa0b12f` stack-coordinate repair is hardened by the same
`dcdc99cc` commit. A call argument loaded through `rsp` can no longer be moved
across an `rsp` adjustment and reinterpreted as a different stack slot. The
real stripped SysV format wrapper returns to its true two-parameter signature
and forwards `arg1`, while the hardened rule declines to change generic impure
folding. See `results/wp3-stack-coordinate-phase.md`.

## Authority and relationship to the roadmaps

`docs/development/roadmap/README.md` remains the canonical roadmap index, and
`docs/development/test-estate/EXECUTION.md` remains its landed-work status
tracker. This file does not create a third independent queue: it supplies the
implementation detail, ordering, tests, measurements, and stop conditions for
the recommendations accepted from this review. When work starts or its status
changes here, the corresponding roadmap item must be added or updated in the
same documentation increment and link back to the relevant work package.

`docs/development/roadmap/real-binary-decompiler.md` remains product sequencing
evidence for real-binary priorities; it is not a second checkbox authority.
Where its ordering conflicts with this plan, the canonical roadmap records the
explicit scheduling decision. The dated review files and this plan provide
evidence and implementation detail; the canonical roadmap answers what is
actually active.

## 1. Objective

Turn the review's ten recommendations into an ordered program that improves
semantic correctness, structural recovery, type fidelity, readability, and
pipeline maintainability without accepting unmeasured regressions.

This plan does not authorize an upstream DecBench issue, comment, or pull
request. DecBench work here is limited to local evaluation and internal
evidence, consistent with `AGENTS.md` and `CLAUDE.md`.

## 2. Non-negotiable rules

1. Follow RED, GREEN, REFACTOR, VERIFY for every behavior change.
2. Preserve a best-effort analyst rendering even when release evidence fails.
   Fail closed on claims and gates, not by hiding the function body.
3. Run correctness changes against execution evidence and structural/score
   evidence together. A lower goto count alone is not success.
4. Keep scored pseudocode deterministic. Diagnostics and provenance belong in
   structured metadata unless a render style explicitly requests annotations.
5. Treat an authoritative declaration and an inferred prototype as separate
   facts. Render the authoritative declaration while retaining any conflict.
6. At equal inputs, session facts, options, and analysis budget, every entry
   point must produce byte-identical pseudocode.
7. Rust remains measured but is reported as a separate language axis. Rust ABI
   implementation is not on the primary C roadmap.
8. Do not delete dormant subsystems until their exact callers, tests, and
   retained responsibilities have been recorded and the deletion has passed
   the full release profile.

## 3. Status vocabulary

- `[ ]` not started
- `[~]` in progress or partially landed
- `[x]` complete and verified
- `[r]` rejected after a recorded experiment
- `[b]` blocked by a named dependency

A work package becomes `[x]` only when its implementation, focused tests,
required corpus gates, documentation, and before/after measurements exist.

## 4. Existing baseline authority

Do not create a parallel baseline ledger. The committed baseline JSON files at
a pinned Git commit are the baseline authority:

- `tests/decompiler_fixtures/baseline.json`
- `tests/decompiler_fixtures/arch_baseline.json`
- `tests/decompiler_fixtures/structural_baseline.json`
- `tests/decompiler_fixtures/defuse_baseline.json`
- `tests/decompiler_fixtures/stripped_divergences.json`
- `tests/open_defects/known_failures.json`

Every result report records the Git revision, build fingerprint, exact command,
and which of these committed files it used. DecBench scores, elapsed time, and
RSS are recorded only in the increment that actually measures them; they are
not prerequisites for starting capability work.

## 5. Dependency order

```text
WP0 minimal measurement and gate integrity
 |
 +--> WP1 bounded MIR trial --> keep MIR or delete it
 +--> WP2 shared pipeline and explicit analysis budgets --> WP3 SSA/origins
 +--> WP4 shadow-mode total structurer <---- typed cases from WP5 when ready
 +--> WP5 typed indirect targets
 +--> WP7A immediate render-level idioms
 +--> WP8 declaration authority
 +--> WP9 machine model increments

WP3 --> WP6 constraint typing
WP3 --> WP7B SSA-expression idioms

WP10 consolidation and deletion follows each accepted replacement; final
release evidence follows the selected set, not the completion of every package.
```

WP1 must precede any competing SSA- or AST-based implementation of the skipped
goto-aware definedness check. Otherwise the MIR trial cannot demonstrate
unique value. WP4 and WP5 depend only on WP0 and should start while WP2/WP3 are
in flight; the current typed CFG and `Cfg::from(lf, ssa)` are sufficient for a
shadow structurer, and indirect-target analysis does not require the new value
identity model.

### Rough effort bands

These are sizing bands for scheduling, not delivery promises. Re-estimate after
the RED fixture or first vertical slice exposes the actual boundary.

| package | rough effort | first independently useful result |
|---|---:|---|
| WP0 | 1-2 days | deduplicated/language-split counts and one honest gate command |
| WP1 | 2 days, hard cap | MIR keep/delete evidence |
| WP2 | 2-4 weeks | two entry points sharing one request/result path |
| WP3 | 4-8 weeks, incremental | one SSA consumer migrated with conservative invalidation |
| WP4 | 3-6 weeks to promotion; shadow in week 2 | condition-DAG shadow result and coverage report |
| WP5 | 1-3 weeks for host jump tables | typed x86 case edges reaching shadow structuring |
| WP6 | 3-6 weeks, incremental | C signedness constraints on one fixture family |
| WP7A | 2-5 days | typed literal spelling and one range-check fusion |
| WP7B | 2-4 weeks, incremental | first SSA-native proved idiom |
| WP8 | 3-7 days | `tail_dispatch` declaration and names rendered correctly |
| WP9 | 4-8 weeks, incremental | one fact class moved behind `TargetSpec` queries |
| WP10 | 1-3 weeks total, spread across migrations | first superseded module removed with release evidence |

## 6. WP0 — Minimal inventory and gate integrity

Purpose: make subsequent changes comparable without delaying capability work.

### Production and tooling changes

- [x] Extend `tools/gen_known_failures.py` to derive a stable binary identity
  from build provenance and content hash.
- [x] Batch known-failure recovery once per binary, reuse rendered text for
  signature parsing, and use bounded binary-level workers. Add language and
  fixture filters, real `--help`, progress control, and resumable per-object
  checkpoints; keep output deterministically sorted across worker counts.
- [x] Preserve O2 and stripped-O2 as distinct observations, but count an
  identical pair once in the primary defect total.
- [x] Add only the generated identity/language fields required to reproduce
  deduplication and language totals; do not expand the schema pre-emptively.
- [x] Update `tools/gen_defuse_baseline.py` and `tools/defuse_ratchet.py` to
  emit and compare C and Rust subtotals separately.
- [x] Add new `scripts/decompiler-gate.sh` with `fast`, `default`, and
  `release` profiles. Reuse `scripts/feature-build-gate.sh` and
  `scripts/decbench-local-gate.sh`; do not duplicate their implementations.
- [x] Make every profile print its revision, build fingerprint, included
  lanes, excluded lanes, elapsed time, and final evidence denominator.
- [x] Reject unknown profiles and incomplete prerequisites.
- [x] Add the strict xfail for the constant-false Duff's-device latch in
  `102_duffs_device-gcc-O2.so::duff_copy` immediately.

### Tests

- [x] Extend `python/tests/test_known_decompiler_failures.py` with schema,
  language-total, and deduplication invariants.
- [x] Batch the strict-xfail consumer once per object and test conventional
  pointer-star spelling, serial/parallel equivalence, and checkpoint/resume
  against real fixture binaries.
- [x] Extend `python/tests/test_defuse_ratchet.py` for language-split totals and
  identical-vs-divergent stripped pairs.
- [x] Add `python/tests/test_decompiler_gate.py` using print-plan and preflight
  contracts to test profile composition and fail-closed behavior without
  executing the expensive profiles.
- [x] Keep `python/tests/test_perf_gate_fails_closed.py` green.

### Gate definitions

- `fast`: build guard, focused Rust tests, Python unit tests that do not build
  the full fixture matrix, Ruff, and `ty`.
- `default`: `fast`, host O0/O2 fixture matrix, all supported architecture
  lanes, structural census, def-use census, fitness and allowlist ratchets,
  and the full Python suite.
- `release`: `default`, feature-build gate, performance/determinism gate,
  stripped divergence lane, and explicitly requested local DecBench evidence.

### Exit criteria

- [x] Raw and deduplicated counts reconcile exactly.
- [x] C and Rust subtotals sum to every overall total.
- [x] The complete 1,676-object inventory regenerates in a bounded run: 203.97
  seconds with eight workers on 2026-09-04, versus the superseded serial run
  still incomplete after 4,213 seconds.
- [x] A deliberately missing lane makes `default` or `release` not-evidence.
- [x] The Duff's-device semantic hole is represented independently of its
  existing `unrecovered` failure.

## 7. WP1 — Two-day MIR production-consumer trial

Purpose: decide whether the roughly 8,700-line MIR/MemorySSA substrate earns a
production role before building a competing verifier.

### Trial question

Use `DefinitionOracle::all_paths_defined` to evaluate path-sensitive
used-before-definition on goto-bearing functions currently skipped by
`src/ir/verify_defs.rs`.

### Files

- modify: `src/ir/mir/mod.rs`
- modify as needed: `src/ir/mir/verify.rs`
- modify: `src/ir/verify_defs.rs`
- modify: `src/ir/health.rs`
- modify: `src/python_bindings/ir/pipeline.rs`
- tests: existing MIR tests under `src/ir/mir/`
- tests: `src/ir/health_tests.rs`
- tests: `python/tests/test_decompiler_defuse_census.py`
- measurements: `tools/gen_defuse_baseline.py`

### Implementation sequence

- [r] RED: a temporary small goto-bearing CFG with a definition on only one
  predecessor proved that MIR reports the missing path while the structured
  walk declines goto-bearing flow. The trial code was removed after rejection.
- [r] A temporary read-only MIR result was exposed through the health record
  without modifying pseudocode, then removed after rejection.
- [r] The temporary record carried `analysis=MIR`, queried value, use site,
  predecessor evidence, and completeness/decline reason.
- [r] Two real-binary probes produced complete clean proofs, but the population
  sweep was stopped after the hard performance criterion failed. The bounded
  A/B evidence and its explicitly limited denominator are recorded in
  `mir-trial-results.md`.
- [x] Do not implement the recommendation 9 AST-label-graph alternative
  during this trial.

### Decision rule

Keep MIR only if, within two working days and below 10% fixture-matrix wall
time overhead, it produces at least one verdict unavailable to the structured
walk or complete clean proofs for the applicable population, and that value is
not cheaper to obtain from the authoritative SSA work in WP3.

If rejected:

- [x] Record results in
  `docs/history/decompiler-review-2026-09-02/mir-trial-results.md`.
- [x] Inventory every production and test reference to `src/ir/mir/`,
  `src/ir/memory_ssa.rs`, and the MIR adapters in `src/ir/memory_objects/`.
- [~] Delete only after porting any independent LLIR invariant checks and
  demonstrating the `release` profile remains green.
- [x] Implement goto-aware definedness over the final AST label CFG; malformed
  label graphs decline the stronger flow-sensitive claim while preserving the
  always-safe whole-function finding.

If accepted:

- [ ] Define MIR as the sole owner of the query and remove the structured
  verifier's overlapping implementation rather than maintaining two answers.

## 8. WP2 — One pipeline, explicit budgets, and checked pass ordering

Purpose: remove semantic differences caused solely by the Python entry point
and make pass repetition/invalidation explicit.

Status: complete. Commit `e7b7de67` closes the final exact-range budget
contract; the 27-test focused WP2 suite covers shared session facts, all-entry-
point equivalence, fresh-process determinism, pipeline reporting, and explicit
incompleteness.

### Production changes

- [x] Introduce a pipeline-owned request and result model in
  `src/python_bindings/ir/pipeline.rs`:
  - `DecompileRequest { va, style, analysis_budget, render_options }`
  - `AnalysisBudget` with explicit callee, discovery, type, CFG, and size
    limits;
  - `DecompileResult` carrying pseudocode, health, completeness, provenance,
    and pipeline fingerprint.
  `d6a65779` lands the request half for module-level and reusable-session
  `decompile_at`: the VA, five explicit discovery limits, render selection,
  debug cache, and analyst overlays now cross one typed boundary. The result
  model and the range/all/many request adapters were initially open. Follow-on
  `5a2d6c86` moves all four entry points onto the same `AnalysisBudget`
  conversion and makes an exact discovered range reuse the ordinary CFG and
  direct-callee facts. `5ea45dca` adds `DecompileResult` for module/session
  single-function requests, carrying rendered text, final AST health, exact
  completeness limits, provenance, and the pipeline fingerprint. `15d044eb`
  makes range/all/many construct the same request and result internally before
  projecting their legacy adapter-specific shapes. `e9518094` begins the
  required budget split with a fingerprinted `CalleeBudget`: its depth now
  bounds both direct-callee and relocation-proven function-table contract
  recovery through the shared pipeline instead of a hidden constant.
  `b3a6543a` separates program-level function-count/total-time discovery limits
  from per-function block/instruction/time CFG limits while preserving their
  exact projection into the discovery engine. `dc303793` replaces the hidden
  render-time type fixed-point cap with a request-owned `TypeBudget`; exhaustion
  keeps the best accumulated facts, and a zero-budget test proves it does not
  erase pre-existing evidence. `87edaeb6` adds `SizeBudget`, which now bounds
  explicit-range fallback bytes and all/many result counts. All five budget
  classes are enforced, fingerprinted, and constructed by every adapter.
- [x] Move common orchestration out of `src/python_bindings/ir.rs` into one
  `decompile_function(session, request)` implementation.
  `41bd90a6` moves prototype refinement, lowering, landing-pad marking,
  lower-stage health tracing, and the AST pass invocation behind one
  pipeline-owned `lower_and_run_ast_passes` boundary. All four adapters consume
  its `PreparedAst`, including exact-range, which previously skipped
  pass-through parameter refinement. `e0588083` then centralizes the immutable
  image-wide render facts in `ProgramRenderContext`; `21f8b29a` centralizes
  debug declarations and layouts in `ProgramDebugContext`; `2ef9c4eb`
  centralizes binary-truth address names and data symbols in
  `ProgramNameContext`; `d900cf1b` centralizes budget conversion and function
  discovery in `ProgramDiscovery`; `1e1ac0a8` centralizes post-lowering
  semantic finalization in `finalize_prepared_ast`; `2f7a6149` centralizes
  declaration selection, type projection, all style rendering, provenance, and
  incompleteness in `render_prepared_ast`. `2ee8fa15` moves the final
  adapter-owned lift/preparation shell behind `decompile_function`, which now
  owns the complete per-function lift-to-render transaction.
- [x] Convert `decompile_at`, `decompile_range_at`, `decompile_all`, and
  `decompile_many` into adapters that create requests and call the same path.
  Module-level and reusable-session `decompile_at` create the typed request;
  all/range/many now share its budget conversion. The first full-text
  differential caught range's synthetic one-block CFG and empty callee facts;
  `5a2d6c86` makes an exact discovered range reuse both authoritative inputs
  while preserving the explicit-window fallback. `41bd90a6` then makes every
  adapter call the same LLIR-to-AST stage. `15d044eb` closes typed request/result
  construction for range/all/many too. `e0588083` removes four copies of the
  image-wide render-context builder, and `21f8b29a` removes the four debug-
  context builders. `2ef9c4eb` removes the four name/data context builders.
  `d900cf1b` removes the four discovery calls and keeps each result paired with
  its exact budgets. `1e1ac0a8` removes four adapter-owned finalization
  sequences while preserving their analyst, debug, exception, frame, and PDB
  semantics. `2f7a6149` removes the four remaining render-policy copies; a
  three-style differential proves DecBench, C, and untyped output agree across
  address, exact-range, all, and many. `2ee8fa15` removes the remaining four
  lift/preparation copies: each adapter now constructs shared contexts and a
  typed request, calls `decompile_function`, and projects only its legacy
  Python return shape.
- [x] Move shared callee-contract preparation through
  `src/python_bindings/ir/callee_contracts.rs`.
- [x] Add checked `PipelineStage` and pass preconditions to
  `src/python_bindings/ir/pipeline.rs`; split into a new
  `src/python_bindings/ir/pass_manager.rs` only when the module-size ratchet
  requires it.
  `74853fcc` adds a fail-closed `PipelineStageTracker` to the production
  per-function transaction for lift, callee facts, LLIR preparation, AST
  preparation, finalization, and rendering. A deliberate Finalized-to-Rendered
  request from the Lifted stage returns the exact expected/actual-stage error.
  `4ea067df` adds one canonical 20-pass AST order and makes every production
  `pass!` invocation check it. Optional passes may be omitted, while unknown,
  repeated, or backward passes return typed `AstPassOrderError` values.
- [x] Replace hand-repeated settle passes with a bounded fixpoint driver that
  records firing and termination reasons. `5f7df194` makes copy/constant
  settling and forward-region/loop settling use one `run_bounded_fixpoint`
  implementation. Each invocation records total rounds, firing rounds, and
  `quiescent` versus `bound_reached`; the real DecBench profile carries both
  reports without changing pseudocode.
- [x] Include analysis-budget identity and pass-version identity in the
  pipeline fingerprint.
  `5ea45dca` defines schema `glaurung.decompile-pipeline/v1`, explicit
  `PIPELINE_PASS_VERSION`, the complete `AnalysisBudget`, style/type/debug
  selectors, and analyst-overlay presence. A unit test proves a budget change
  changes fingerprint identity.

### Tests

- [x] Extend `python/tests/test_decompiler_session.py` for shared-session facts
  and explicit budgets. `357579c4` exposes exact program-fact ownership and
  proves two distinct discovery budgets retain distinct discovery/call-graph
  artifacts while reusing one compatible program environment and one immutable
  symbol/type fact set. Cache clearing removes budget-dependent facts and
  intentionally retains image-derived facts.
- [x] Add `python/tests/test_decompiler_entrypoint_equivalence.py` covering all
  four entry points at equal budgets.
  All four paths now emit byte-identical `tail_dispatch`, including its
  indirect-call arguments, in DecBench, C, and untyped styles with equal block,
  instruction, and per-function time budgets. `c077ccca` separates
  `decompile_all`'s output `limit` from its public discovery `max_functions`,
  exposes the same discovery limit on exact-range, and makes single-function
  size identity use that explicit limit. The test now constructs equal
  discovery, CFG, callee, type, and size budgets across all four entry points.
- [x] Extend `python/tests/test_decompiler_determinism.py` for fingerprints and
  function-order independence. `c907121a` serializes the complete fingerprint
  canonically into opt-in pipeline evidence and proves, across fresh processes,
  that reversing a three-function request changes neither each function's
  pseudocode nor its fingerprint. Serialization remains lazy when profiling is
  disabled.
- [x] Extend `python/tests/test_pipeline_profile_report.py` for pass order,
  firing counts, and bounded fixpoint termination. `5f7df194` validates and
  aggregates both production fixpoint reports, including impossible counts and
  the closed termination vocabulary. `a7797e28` emits the checked semantic
  transaction as one ordered `pipeline_stages` sequence, rejects malformed or
  duplicate traces, and proves the real production order is lift, callee facts,
  LLIR preparation, AST preparation, finalization, then rendering without
  changing pseudocode.
- [x] Test that a deliberately lower range budget differs only with an
  explicit completeness reason. The exact-range `tail_dispatch` regression
  changes only `max_blocks` from 4096 to 1, requires both calls to retain a
  rendered function body, and proves the constrained result names exactly the
  fired `max_blocks=1` limit while the complete result remains unmarked.

### Exit criteria

- [x] Equal budget produces byte-identical pseudocode for the same function
  across all entry points.
- [x] No entry point independently performs discovery, naming, or callee
  analysis.
- [x] Invalid pass order fails in focused tests. `74853fcc` proves this for
  coarse semantic stages; `4ea067df` proves it for individual AST passes and
  separately rejects unregistered passes.
- [x] Every repeated pass is justified by recorded invalidation or a declared
  fixpoint, not duplicated orchestration. The two intentional AST settling
  repetitions are named bounded fixpoints with reported termination.

## 9. WP3 — Authoritative SSA, stable value identity, and origins

Purpose: move dataflow work off display names and preserve instruction
provenance through lowering.

### Core model

- [~] Add a pipeline-owned, versioned `SsaInfo` near the existing SSA
  implementation under `src/ir/`. `925dc002` lands the owner and `09522773`
  retains it across definedness normalization, prototype recovery, and return
  materialization; ownership does not yet persist through AST lowering.
- [x] Define explicit invalidation classes: CFG changed, definitions changed,
  uses changed, types changed, and presentation-only change.
- [x] Make an unclassified mutating pass conservatively return
  `Invalidate::All`. Migrate passes one at a time to narrower change sets; do
  not require roughly 100 passes to convert before the first consumer lands.
  The enum default is `All`; the remaining pass migrations are tracked by the
  following ratchet item.
- [ ] Require every newly added mutating pass to declare a change set, and
  ratchet the count of legacy `Invalidate::All` passes downward.
- [~] Recompute or repair SSA before the next consumer when invalidated. The
  definedness-normalization and return-materialization mutations declare
  `Uses` and reconstruct before indirect-target, structuring, and
  value-numbering consumers; other mutating passes remain to migrate.
- [~] Preserve opaque SSA value identity through AST lowering. Commit
  `f05c9a5d` carries exact or explicitly ambiguous `SsaValue` candidates beside
  value-numbered LLIR and the lowered production AST, and migrates float-role
  projection as the first product consumer; `af65c260` migrates optimized
  DWARF register-local recovery. Multi-output definitions, AST
  pass-native identities, and the remaining consumers are still open.
- [~] Add a compositional instruction-origin set to expressions/statements;
  unions must be deterministic and deduplicated. `7bea3314` defines the
  canonical set and `59840017` adds transparent statement ownership with
  union-without-nesting semantics. Commit `8cb7d171` preserves that ownership
  through the enabled AST pass surface and fixes origin-transparent structured
  return-width reasoning. Commit `cda7ab73` additionally makes post-pipeline
  exception recovery origin-transparent and unions contributing origins into
  its synthesized structured nodes. Commit `cb9e5b10` migrates six more
  control-oriented wildcard consumers and preserves composed origins on their
  synthesized statements. Commit `52914784` makes guarded-switch recovery
  transparent through recognition, recursion, and mutation and preserves the
  union of each removed guard, discriminator copy, and inner switch on the
  replacement. Commit `f7b47953` makes every guard-chain rewrite transparent
  and unions origins across removed guards, labels, gotos, duplicate
  assignments, and terminal tails. Commit `3b7d8a95` makes
  both switch-ladder synthesis forms and final join-break cleanup transparent,
  preserving unions across every consumed comparison, dispatch, label, goto,
  case, and join statement. Commit `a807b2d0` makes latch-predicate folding and
  both loop-carrier coalescers transparent and transfers each removed
  contributor to its surviving loop. Commit `c51a116d` makes AAPCS64 and SysV
  indirect-result hinting plus post-promotion binding transparent while
  preserving call ownership. Commit `02b0da5c` makes packed-vector batch,
  scalar-view bridge, and nested-control recovery transparent, unions every
  consumed lane and bridge origin into the two synthesized wide operations,
  and retains the one-consumer safety proof under nesting. Commit `e92d7248`
  additionally makes assignment-diamond, guarded-return,
  created-select-return, and `try`/`catch` traversal transparent, distributing
  exact origin unions to the semantic replacements. Its three whole-Python
  improvements are parent/tip A/B-confirmed with zero new failing nodes.
  Commits `b6172031` and `a0917da5` make the convention-generic recovered-
  layout folds transparent, union removed setup owners into the call, and
  enforce the existing pure-expression boundary so attributed ARM frame loads
  remain available to the stronger general argument scan. The complete
  stripped map is neutral and the whole-Python boundary improves by one node
  with no addition.
  Commit `c291328a` then migrates cdecl32 outgoing stores, lowered push pairs,
  cleanup proof, and stack rebasing. Consumed setup owners join the call and
  removed decrement owners remain on the synthesized net adjustment. Its
  stripped map is neutral, while controlled release A/B proves two
  whole-Python failures removed with zero additions.
  Commit `e403de27` completes the AAPCS call-argument surface: locked contract
  lookup, pure-VFP setup, outgoing stack areas, and stack-phase refusal all see
  attributed statements, with exact call-owner preservation. Controlled
  release A/B proves two ARM32 execution failures removed and one stripped
  improvement without a regression.
  Commit `9942f948` then migrates stack-canary recognition and collapse:
  attributed save, reload, comparison, branch, failure-call, and nested
  structured statements remain visible, and synthesized comments receive the
  complete deterministic union of removed owners. Both the stripped map and
  exact 211-node whole-Python boundary are neutral.
  Commit `8989cecc` next migrates integer-pair return recognition and mutation,
  preserving the return owner and refusing an explicitly floating low result.
  Commit `82a95253` batches six origin-transparent call-analysis consumers
  across `call_args.rs`, `captured_defs.rs`, `enclosing_slots.rs`,
  `fold_one_call.rs`, and `return_attribution.rs`; it preserves carriers while
  recognizing reads, writes, calls, alias barriers, enclosing definitions,
  SSE-pair producers, and literal-format proofs.
  Commit `7d531781` closes final-preparation omissions in machine-frame
  cleanup, widening, comparison fusion, and DWARF-field invalidation. Commit
  `4b35aeab` then makes dead-store recognition, nested-exit safety, promoted-
  store cleanup, and unused call-result clearing origin-transparent. The latter
  restores effect-only calls without losing their statement owner and prevents
  an attributed exit from making a reaching value look dead. See
  `results/wp3-final-cleanup-origins.md`.
  Commit `025937a7` next migrates direct-output cleanup, balanced-stack caller
  arity, named and frame-object parameter homes, and wide dual-role definition
  evidence. Seven focused cases were observed red before repair; attributed
  readers and in-place rewrites now match their unwrapped behavior without
  losing surviving owners. The audit also identifies bank-return composition
  as a non-mechanical boundary: it synthesizes stores and returns, so its
  migration follows the explicit fold/hoist/duplication policy rather than an
  ad hoc wrapper bypass. See `results/wp3-output-value-origins.md`.
  Commit `6068a59c` completes that first complex boundary: stack-resident bank
  composition sees through carriers, while register-resident materialization
  copies each exact assignment/call/return owner onto every synthesized store
  or rewritten return. Both transformation tests were observed red first; all
  20 module tests and the eight exact aggregate-return lanes pass. See
  `results/wp3-banked-return-origins.md`.
  Commit `876bddf6` follows through the adjacent call-result loop boundary:
  attributed breaks remain exit barriers and attributed boxed-clause calls do
  not request an impossible compatibility insertion. Both observed-red tests,
  all 15 module tests, and eight exact call-result lanes pass. See
  `results/wp3-call-result-loop-origins.md`.
  Commit `c6a42332` then migrates the goto-aware final-source verifier and
  authoritative pointer-boundary refinement. Both observed-red tests, all 66
  touched-module tests, and the eight architecture/optimization declaration
  invariant cells pass. See `results/wp3-verification-pointer-origins.md`.
  Commit `bd31420d` next makes fallback canonical loop naming transparent to
  attributed loop, initializer, step, and accumulator statements without
  reassigning their independent owners. Its observed-red test, all 18 naming
  tests, and the four exact `skip_odd_sum` host lanes pass. See
  `results/wp3-canonical-loop-naming-origins.md`.
  Commit `51d3c9df` then migrates the ARM32 frame recognizer end to end:
  attributed prologue, epilogue, nested-return, and helper reads preserve the
  transactional balance proof, while each synthesized machine-frame comment
  receives the exact union of the instructions it replaces. Its observed-red
  test, all nine module tests, and the exact ARMv7 A32 `while_prefix` cell pass.
  See `results/wp3-arm32-frame-origins.md`.
  Commit `6e4cd9ec` follows with the canonical x86 frame prologue: attributed
  pushes, frame-pointer setup, optional dead allocation predicates, and stack
  allocation remain recognizable, and the replacement comment receives their
  exact origin union. Its observed-red test, all 31 module tests, and the two
  exact host O0 `classify` cells pass. See `results/wp3-x86-frame-origins.md`.
  Commit `4dcaa1f5` then migrates balanced cdecl32 call padding through top-level
  and nested structured control. Each surviving call receives the exact union
  of its own owner and the removed padding/cleanup owners without weakening
  the arity and balance proof. Its observed-red test, all 32 x86 frame tests,
  and two exact i386 O0 call functions pass. See
  `results/wp3-cdecl-alignment-origins.md`.
  Commit `ce8d092a` completes the adjacent aligned-entry-frame transaction:
  attributed entry setup and teardown remain recognizable, while the two
  synthesized comments receive separate exact unions for the disjoint machine
  ranges they replace. Its observed-red test, all 33 x86 frame tests, and the
  exact checked-in MinGW PE32 `main` integration test pass. See
  `results/wp3-cdecl-entry-frame-origins.md`.
  Commit `5db4b91b` closes the adjacent MinGW runtime-call omission: attributed
  zero-argument `___main` cleanup now sees through the origin carrier, deletes
  only that runtime bookkeeping, and does not reassign its owner to an
  unrelated surviving call or return. Its observed-red test, all 34 x86 frame
  tests, and the exact checked-in MinGW PE32 `main` integration test pass. See
  `results/wp3-mingw-runtime-origins.md`.
  Commit `8bfadfa9` then migrates the exact hardened-return x87 scrub: wrapped
  `8 x fldz; 8 x fstp` sequences remain recognizable, incomplete sequences
  still fail closed, and the replacement comment receives the exact union of
  every consumed x87/stack-teardown owner while the return stays independent.
  Its observed-red test and all 35 x86 frame tests pass; no checked-in fixture
  currently exercises `-fzero-call-used-regs=all`. See
  `results/wp3-x87-scrub-origins.md`.
  Commit `96e86313` completes the ordinary x86 epilogue transaction: canonical
  `leave`, standalone pop, promoted-stack restore, pre-rematerialized pop, and
  second-round teardown forms all see attributed statements. Each replacement
  comment receives the exact consumed-owner union and each return remains
  independent. Its observed-red test, four focused ownership assertions, all
  39 x86 frame tests, and both exact host O0 `classify` cells pass. See
  `results/wp3-x86-epilogue-origins.md`.
  Commit `2efa3106` then migrates the AArch64 frame transaction: canonical and
  promoted prologues, paired `fp`/`lr` restores, and adjacent stack teardown
  see attributed statements, while replacement comments receive exact
  consumed-owner unions and returns remain independent. Its observed-red
  prologue test, focused epilogue ownership test, all 12 module tests, and one
  exact AArch64 O0 `classify` cell pass. See
  `results/wp3-aarch64-frame-origins.md`.
  Commit `7c2fc34b` begins the next enabled cleanup boundary: attributed
  `ret = C; return C` pairs now collapse in supported structured bodies and
  union the removed assignment owner onto the surviving return, while
  mismatched constants remain unchanged. Its observed-red test, all four
  return-fold module tests, and both exact host O0 `classify` cells pass. See
  `results/wp3-constant-return-origins.md`.
  Commit `1c909df4` completes the adjacent exhaustive-return transaction:
  attributed if/switch control, arm definitions, optional breaks, epilogue
  comments, and shared returns retain exact ownership through joined-return
  recovery. Shared-tail owners are copied into every newly materialized return
  while control and arm-specific owners remain disjoint. Both focused tests
  were observed red; all six module tests and four exact O0 if/switch cells
  pass. See `results/wp3-exhaustive-return-origins.md`.
  Commit `91432a22` closes the remaining raw lexical boundary in label cleanup:
  attributed labels and return/goto/indirect-goto/break transfers now delimit
  unreachable runs, while removed unreachable mappings disappear and surviving
  owners remain exact. Its observed-red test, all 20 label-prune tests, and both
  exact host O0 `classify` cells pass. See
  `results/wp3-unreachable-tail-origins.md`.
  Commit `0c7b4e0f` migrates the first declaration/render consumer: attributed
  promoted or debug-proven integer definitions now participate in the same
  safe inline-declaration proof as unwrapped statements, producing
  `int local = value` without weakening prior-read/write or loop-scope refusal.
  Its observed-red rendering test, three adjacent declaration controls, and
  both exact host O0 `while_zero_trips` cells pass. See
  `results/wp3-inline-scalar-origins.md`.
  Commit `db2e7735` adds render-time structured line mappings to the opt-in
  Python batch result and CLI JSON. It records canonical statement origins at
  the line actually emitted, without parsing pseudocode; default native tuple
  shapes and scored text remain unchanged. The exact real `classify` result
  proves both non-contiguous address sets and one instruction contributing to
  several output lines. See `results/wp3-structured-line-mappings.md`.
  Commit `9b10f06e` adds the expression-level carrier and canonical
  attach/unwrap/union helpers, makes all 87 compiler-enumerated exhaustive
  consumers explicitly transparent, and keeps both renderers byte-neutral.
  Commit `3c5c74b9` makes the first bounded production attachment: removing a
  single-use temporary transfers its definition origins to the exact
  reconstructed expression subtree, while the surviving statement retains the
  complete union. Its observed-red test, 102 touched-module tests, and the
  four-lane/48-function `01_conditional_polarity` family pass. A release A/B
  caught and repaired every exposed copy/fold/render regression, leaving the
  exact `classify` text byte-identical to the clean parent. Universal
  expression attribution and the remaining non-exhaustive matcher audit remain
  open; see `results/wp3-reconstructed-expression-origins.md` and
  `results/wp3-expression-origin-carrier.md`.
  Commits `f30167f7` and `b269a3f2` extend that production boundary through
  every return fold that replaces an ABI result assignment, including
  exhaustive `if`/`switch` joins. Returned values retain their definition
  owners while surviving return statements retain the definition/control-
  transfer unions. All four ownership assertions were observed red, all seven
  touched-module tests pass, and the exact four-cell host O0 conditional/switch
  slice remains green on a fresh release build; see
  `results/wp3-return-expression-origins.md`.
  Commit `86ac95a6` then completes expression-owner transfer for all four
  adjacent def/use movements: exactly-once effectful scratch, promoted value,
  eager guard, and consumed-and-overwritten value. All four ownership tests
  were observed red, all 19 touched-module tests pass, and a release-built
  8-lane/24-function effectful-select, guarded-dispatch, and conditional slice
  remains entirely green; see `results/wp3-adjacent-expression-origins.md`.
  Commit `fb878925` next gives every generic register-call argument its own
  setup origin and composes earlier scratch-definition owners through the
  backward scan. Its disjoint two-argument test was observed red, all 110
  parent call-argument tests pass, and the release-built 52-function call-shapes
  fixture remains entirely green; see
  `results/wp3-register-argument-expression-origins.md`. Generic stack
  arguments and specialized recovered-layout/cdecl/AAPCS producers remain
  open. Commit `5f8dec01` then attributes both generic SysV stack forms:
  preallocated outgoing-area and balanced-push argument expressions receive
  only their exact value-store owners, while allocation, call, and cleanup
  owners remain on the call statement. Both observed-red tests, all 111
  call-argument tests, and the exact four-cell release-built `call_into_spill`
  canary pass; see `results/wp3-sysv-stack-argument-expression-origins.md`.
  Commit `76753c05` applies the same exact value-store ownership rule to the
  generic AAPCS outgoing stack area and proves the owner survives
  scratch-register substitution into the final source-ordered arguments. Its
  observed-red helper, four AAPCS tests, 111 call-argument tests, and exact
  four-cell ARM release A/B are neutral; the legacy `armv7:O0` cell is the same
  pre-existing failure on parent and tip. See
  `results/wp3-aapcs-stack-argument-expression-origins.md`. Specialized
  recovered-layout, cdecl32, hard-float, and table-call expression producers
  remain open. Commit `bb98a3a9` next attributes convention-generic recovered-
  layout arguments from their adjacent setup definitions and composes promoted-
  spill definitions through exact substitution; proven untouched live-ins stay
  independent. Both ownership cases were observed red, all 111 call-argument
  tests pass, and the 12-cell cross-ABI `call_into_spill` release A/B is exactly
  neutral, including the same pre-existing legacy `armv7:O0` failure. See
  `results/wp3-recovered-layout-expression-origins.md`. Specialized cdecl32,
  hard-float, and table-call fallback expression producers remain open. Commit
  `e68ff86f` next attributes cdecl32 preallocated-store and lowered-push
  arguments to their exact value stores. Stack decrements remain on the
  synthesized net adjustment, while the call keeps every consumed setup owner.
  Both forms were observed red, all 111 call-argument tests pass, and the exact
  i386 O0/O2 `call_into_spill` release A/B remains 2/2 green; see
  `results/wp3-cdecl32-argument-expression-origins.md`. Hard-float and
  table-call fallback expression producers remain open. Commit `a756a6d5`
  then attributes each pure-VFP hard-float argument to its distinct setup
  assignment without changing the contiguous-prefix or mixed-bank refusal.
  Its observed-red ownership test, four AAPCS tests, all 111 call-argument
  tests, and two exact real ARM hard-float tests pass on a fresh release build;
  the two A32 complex-float canaries remain identically known-failing. See
  `results/wp3-hard-float-argument-expression-origins.md`. The table-call
  reaching-value fallback remains the final identified call-argument producer.
  Commit `f2e69784` closes it by preserving each attributed versioned enclosing
  definition inside `EnclosingSlots`; nested table calls now receive the exact
  owners on their argument expressions while unversioned or clobbered values
  still decline. Its observed-red test and all 111 call-argument tests pass,
  and the exact eight-function fixture-95 release A/B is neutral at three
  passes and the same five pre-existing failures. See
  `results/wp3-enclosing-call-argument-expression-origins.md`. The currently
  identified call-argument expression producer family is complete; universal
  expression attribution and the remaining SSA/invalidation migrations remain
  open. Commit `4c19cb2e` then migrates the adjacent stack-idiom expression
  constructor: a rematerialized push value keeps its prior owner and receives
  the exact value-store owner, while the push statement retains the decrement/
  store union. Its observed-red test, all 11 stack-idiom tests, and four exact
  release-built flag-roundtrip cells pass; see
  `results/wp3-stack-idiom-expression-origins.md`.
  Commit `97aef0c3` then begins the bounded constant-fold migration. Inclusive
  comparison recovery now sees attributed equality and strict-less children
  and places their deterministic origin union on the surviving `<=`
  comparison, without weakening operand, signedness, or relation checks. Its
  observed-red test and all 59 constant-fold tests pass, including the
  module's checked-in real-binary end-to-end canary; see
  `results/wp3-inclusive-comparison-expression-origins.md`.
  Commit `65162531` follows through the adjacent width-proved terminal
  mixed-view relation. Attributed terminal test, relation, equality, and
  signed-less nodes now recover the same readable `K < signed(x)` expression,
  and nested carriers created by an inner fold flatten into their canonical
  four-owner union. Follow-on `2fccded5` closes the shared comparison-to-zero
  boundary for this fold, eager boolean recovery, and exact-boolean inversion:
  attributed zero operands no longer block recognition and retain their owner.
  Its strengthened observed-red test and all 74 constant-fold tests pass; see
  `results/wp3-terminal-relation-expression-origins.md`.
  Commit `6c737361` next makes subtraction zero-test recovery transparent:
  attributed `(x - y) == 0` and `!= 0` forms recover their direct readable
  relation and preserve the deterministic union of the outer comparison and
  consumed subtraction/zero owners. Its observed-red test and all 61
  constant-fold tests pass; see
  `results/wp3-subtraction-relation-expression-origins.md`.
  Commit `5e04d66a` then applies the normative hoisting contract to literal
  selects: an attributed constant predicate is recognized, the chosen arm
  keeps its owner and receives the consumed condition/select owners, and the
  unreachable arm's owner is excluded. Its observed-red four-owner test and
  all 62 constant-fold tests pass; see
  `results/wp3-constant-select-expression-origins.md`.
  Commit `02791f18` next makes full-width cdecl32 parameter-address loads
  transparent. Attributed `Deref(StackAddr(argN))` recovers the parameter and
  retains the exact address/load owner union, while partial-load and non-
  parameter refusal remains unchanged. Its observed-red test and all 63
  constant-fold tests pass; see
  `results/wp3-parameter-load-expression-origins.md`.
  Commit `3b1f34ca` then makes repeated-condition select collapse compare
  semantic predicates through their carriers and preserves the removed inner
  select/condition owner union while excluding the unreachable prior value.
  Its observed-red test and all 64 constant-fold tests pass; see
  `results/wp3-repeated-select-expression-origins.md`.
  Commit `22cb5827` next makes equal-or-wider inner-cast subsumption
  transparent. The surviving outer cast receives the consumed inner-cast
  owner while the source value keeps its independent subtree owner; narrowing
  refusal is unchanged. Its observed-red test and all 65 constant-fold tests
  pass; see `results/wp3-subsumed-cast-expression-origins.md`.
  Commit `66e533d7` then makes safe eager SETcc boolean-tree recovery
  recursively transparent. Terminal, byte-view, tree, and predicate-leaf
  owners survive on the recovered logical expression while memory/effect and
  missing-byte-view refusals remain unchanged. Its observed-red test and all
  66 constant-fold tests pass; see
  `results/wp3-eager-boolean-expression-origins.md`.
  Commit `1647953d` next makes observed-mask simplification transparent to an
  attributed partial-register merge. The low-bit predicate retains its merge
  and observation owners, while the provably masked-out high-parent owner is
  excluded. Follow-on `997ec48c` makes the entry matcher transparent to an
  attributed mask constant and retains that additional owner without reviving
  the dead parent. Its strengthened observed-red test and all 73 constant-fold
  tests pass; see
  `results/wp3-observed-mask-expression-origins.md`.
  Commit `14eef6d2` then makes safe constant arithmetic transparent to operand
  carriers. Attributed constants fold normally and the result retains the
  enclosing operation plus both operand owners; division-by-zero and invalid-
  shift refusals are unchanged. Its observed-red test and all 68 constant-fold
  tests pass; see `results/wp3-constant-arithmetic-expression-origins.md`.
  Commit `e2df3e60` next makes signed and unsigned constant comparisons
  transparent to operand carriers. The folded boolean retains the enclosing
  comparison plus both operand owners. Its observed-red test and all 69
  constant-fold tests pass; see
  `results/wp3-constant-comparison-expression-origins.md`.
  Commit `ff0ced1c` then makes same-semantic-operand identities transparent to
  distinct carriers. The `x ^ x`, `x - x`, `x & x`, and `x | x` family now
  preserves the enclosing operation and both operand owners. Its observed-red
  test and all 70 constant-fold tests pass; see
  `results/wp3-same-operand-expression-origins.md`.
  Commit `3627ca65` next makes the full neutral/absorbing constant-identity
  family transparent to carriers. Neutral folds retain the survivor and
  constant owners; absorbing folds retain the determining constant but exclude
  the genuinely irrelevant value owner. Its observed-red policy test and all
  71 constant-fold tests pass; see
  `results/wp3-constant-identity-expression-origins.md`.
  Commit `c79f57db` then makes redundant literal and exact-boolean cast removal
  transparent to the inner carrier. The replacement retains both inner-value
  and enclosing-cast owners, while the width-bearing shift-left refusal remains
  unchanged. Its observed-red test and all 72 constant-fold tests pass; see
  `results/wp3-redundant-cast-expression-origins.md`.
  Commit `64781964` next makes ARM/AArch64-style address reconstruction
  transparent to page/base and offset carriers. The final address retains both
  operand owners plus the enclosing arithmetic owner without weakening the
  non-additive, reversed-subtraction, or stale-name refusals. Its observed-red
  test and all 73 constant-fold tests pass; see
  `results/wp3-address-reconstruction-expression-origins.md`.
  Commit `072412ce` next makes the common x86 associative XOR-cancellation
  shape transparent to carriers. Repeated semantic flags cancel despite
  distinct owners, and the surviving relation retains every consumed flag,
  nested-XOR, relation, and enclosing-operation owner. Its observed-red test
  and all 74 constant-fold tests pass; see
  `results/wp3-xor-cancellation-expression-origins.md`.
  Commit `dfa2fa22` then makes the storage-width fold boundary transparent to
  an enclosing carrier. Store-proved redundant casts and masks still collapse,
  with the cast/value owners flattened into one canonical set. Its observed-red
  test and all 75 constant-fold tests pass; see
  `results/wp3-stored-value-expression-origins.md`.
  Commit `5289e459` then makes the typed-declaration view pass transparent to
  outer-cast, inner-cast, and source carriers. Its exact width/signedness proof
  and return-promotion refusal remain unchanged while the surviving source
  receives the canonical three-owner union. Its observed-red test and all 76
  constant-fold tests pass; see `results/wp3-typed-view-expression-origins.md`.
  Commit `251ae25e` applies the same rule to typed comparison-extension
  removal. Both compared operands retain their exact outer-cast, inner-cast,
  and source owners, and the shared terminal mixed-view relation composes the
  cast owners into its readable replacement. Its strengthened observed-red
  test and all 76 constant-fold tests pass; see
  `results/wp3-typed-comparison-expression-origins.md`.
  Commit `8c84c4ed` then makes the safe eager-Boolean recognizer transparent to
  an attributed byte-mask constant. The recovered short-circuit tree retains
  the mask owner alongside its mask-tree, cast, predicate-tree, and terminal-
  test owners without weakening the side-effect, leaf-count, or byte-view
  gates. Its strengthened observed-red test and all 76 constant-fold tests
  pass; see `results/wp3-boolean-mask-expression-origins.md`.
  Commit `c0e296e7` then makes nested observed-mask proofs transparent to an
  attributed inner mask tree and constant. The surviving predicate retains the
  owners that prove the stale high bits irrelevant while excluding the stale
  value owner itself; mask-disjointness remains mandatory. Its strengthened
  observed-red test and all 76 constant-fold tests pass; see
  `results/wp3-disjoint-mask-expression-origins.md`.
  The remaining wildcard consumers and universal production attribution remain
  open.

### Migration targets

- [ ] Move copy propagation from `src/ir/copy_prop/` to authoritative SSA
  consumption before AST lowering.
- [ ] Move constant folding, dead-store elimination, and DCE in bounded
  increments, one pass at a time.
- [~] Remove semantic parsing of `ret`, `argN`, `local_`, and `#version` only
  after each consumer has a typed identity replacement.
  `f05c9a5d` removes `#version` parsing from production float-role projection;
  `af65c260` removes it from optimized DWARF register-local recovery.
  Compatibility and other product consumers remain. The latter migration also
  exposed that `gcc-O2-vsa_double_args` had been a false pass: one display-name
  merge hid the unresolved SysV `al` variadic live-in. That cell is now an
  honest strict xfail rather than a semantic identity exception.
- [ ] Remove `tag_phys` from `src/ir/value_number/tagging.rs` after its last
  typed consumer lands.
- [ ] Remove `remap_type_map` callers in `src/python_bindings/ir.rs` and
  `src/python_bindings/ir/type_maps.rs` after value-keyed type maps are live.
- [ ] Keep naming as a render mapping, not a program rewrite.

### Origin and mapping surface

- [~] Extend AST definitions in `src/ir/ast.rs` or the owning AST module with
  `OriginSet`. Commit `7bea3314` lands the canonical sorted, deduplicated set,
  deterministic union, and exact clone behavior. Commit `59840017` gives
  statements a transparent carrier, converts the 64 exhaustive consumers, and
  proves attributed loop clauses render byte-identically. Commit `8cb7d171`
  converts the remaining enabled pass matches identified by the corpus sweep
  to inspect semantic statements without discarding their carriers and attaches
  each lowered LLIR instruction VA at the block-lowering boundary. Expressions and
  structured control nodes still need direct ownership where statement-level
  attribution is insufficient. Commit `9b10f06e` adds the corresponding
  expression carrier, deterministic union-without-nesting, semantic access,
  and explicit transparency at every exhaustive expression consumer. It does
  not yet attach origins to production expression nodes.
- [~] Thread origins through lowering, expression rewrites, structuring, tail
  duplication, and rendering. Commit `8cb7d171` makes enabled statement
  consumers and all three renderers preserve or ignore the carrier without
  changing statement meaning. Block lowering attaches each LLIR instruction VA,
  and `cda7ab73` plus `cb9e5b10` migrate exception recovery and six
  control-oriented wildcard consumers. Commit `52914784` adds the guarded-
  switch consumer, including direct, copied-discriminator, speculative, and
  early-return shapes. Commit `f7b47953` adds contradictory, terminal-return,
  redundant-copy, shared-assignment, and shared-exit guard-chain rewrites.
  Commit `9b10f06e` establishes expression ownership's carrier and exhaustive
  consumer boundary. Production attachment, composition through expression
  reconstruction, and the remaining non-exhaustive matcher audit must finish
  before universal attribution.
- [x] Expose line-to-address mappings from the Python binding as structured
  data; do not infer them by parsing rendered text. Commit `db2e7735` adds an
  opt-in sixth batch-result field with ordered `line_number`/`addresses`
  records and exposes the same records in CLI JSON.
- [x] Define non-contiguous origin behavior for folded, hoisted, and duplicated
  nodes. The normative contract is:
  - an in-place rewrite retains the exact existing owner;
  - a fold unions the sorted, deduplicated origins of every consumed semantic
    contributor with any owner already on the surviving replacement;
  - a hoisted unchanged node retains its own origins, and additionally unions
    the owners of control nodes consumed to make it unconditional;
  - every proved duplicate receives the complete original origin set; origins
    are never partitioned among clones, including when the original already
    represents a fold;
  - purely synthetic scaffolding has an empty origin unless it represents
    consumed machine semantics; a pass must never invent a nearest address;
  - deletion of genuinely dead semantics may remove its mapping, but must not
    transfer it to an unrelated survivor.
  `OriginSet` remains the canonical sorted/deduplicated representation and the
  structured Python mapping must permit one instruction to own multiple output
  nodes. Commit `6068a59c` supplies the first transformation-level proof:
  banked-return materialization clones exact owners onto every synthesized
  store and rewritten return. Commit `db2e7735` supplies the structured Python
  exposure above.

### Tests

- [~] Unit tests for SSA invalidation and reconstruction. The first three tests
  prove conservative default invalidation, revisioned reconstruction, and that
  type/presentation-only changes preserve value identity. The next three prove
  identity survival through lowering, exact opaque consumer lookup, and
  fail-closed ambiguity after phi-copy coalescing.
- [x] Unit tests for deterministic origin union and duplication. Five focused
  tests at `7bea3314` cover non-contiguous canonical construction,
  commutative/idempotent union, and independent duplicated sets; `59840017`
  adds union-without-nesting and byte-identical C/scored rendering. Commit
  `9b10f06e` adds the matching expression-level union, semantic-unwrapping, and
  byte-identical C/scored-rendering contract.
- [ ] Extend `python/tests/test_dectest_equivalence.py` for byte neutrality
  during identity-only migrations.
- [x] Add `python/tests/test_decompiler_line_mappings.py` for one-to-many and
  non-contiguous mappings. Its exact release-built `classify` cell also proves
  legacy tuple-shape compatibility and repeated-call determinism.
- [~] Run the 419-pair output identity sweep after each migrated pass. The
  invalidation, persistent-lifecycle, and first opaque-identity consumer slices
  are byte-identical across all 419 lanes; repeat this gate for every
  subsequent identity-only migration. The statement carrier at `59840017`
  retains the exact same JSON SHA-256 and zero infrastructure problems.

### Exit criteria

- [ ] No product consumer parses display names to identify semantic values.
- [ ] SSA construction occurs only on initial demand or declared invalidation.
- [ ] Origins survive every enabled pass and produce deterministic mappings.
- [ ] The fixture matrix is byte-identical until an intentionally output-
  changing work package begins.

## 10. WP4 — Total, locally degrading structurer

Purpose: replace whole-function structural fallback with a total algorithm
that preserves honest local gotos when required.

### New implementation boundary

- [x] Create `src/ir/structure_v2/` rather than mutating the current structurer
  in place during development.
- [x] Before adding the directory, record its temporary, bounded architecture
  growth in `tools/fitness_baseline.json` and the relevant reviewed-large-module
  allowlist. The acceptance must name WP4, its expected removal/replacement
  target, and an expiry condition at v2 promotion; do not let the fitness gate
  fail merely because the approved shadow implementation exists.
  The approval now permits nine files capped at 4,400 total lines. The first
  increase to 4,000 kept the rendering adapter as an explicit `render.rs`
  boundary; the additional 400-line allowance is pre-registered for the first
  typed-switch recovery, independent verification, and rendering slice rather
  than allowing those concerns to leak into CFG discovery. The same promotion
  or abandonment expiry still applies.
- [~] Suggested modules:
  - `mod.rs`: feature flag, public contract, and shadow comparison;
  - `cfg.rs`: normalized typed CFG input;
  - `dominators.rs`: dominance/post-dominance and loop forest;
  - `conditions.rs`: reaching-condition representation and simplification;
  - `region.rs`: multi-exit region algebra with `Return`, `Break`, `Continue`,
    `Sequence`, `If`, `Loop`, `Switch`, and local labelled region;
  - `recover.rs`: deterministic region construction;
  - `verify.rs`: block and edge accounting;
  - `cleanup.rs`: bounded tail duplication and else-after-terminal flattening.
  The boundary now has `mod.rs`, `cleanup.rs`, `conditions.rs`,
  `dominators.rs`, `local.rs`, `recover.rs`, `region.rs`, and `verify.rs`, while
  reusing v1's typed `Cfg` directly. `render.rs` conservatively adapts verified
  acyclic trees into the existing AST lowerer and C-like printer. `recover.rs`
  now constructs a deterministic
  `Sequence`/`If`/`Block`/`Return` tree for acyclic single-entry candidates and
  `Loop`/`Break`/`Continue` nodes for reducible loops. The real `early_return`,
  `dowhile_atleastonce`, and multi-exit `loop_return_on_neg` binaries are green;
  the latter keeps distinct exit regions before their singly owned shared
  return. Irreducible SCCs now become separately owned local-labelled
  definitions with explicit entry gotos and structured exit paths; the real
  two-entry fixture and the nested irreducible fixture both produce verified
  trees, and the latter retains its surrounding natural loop. An independent
  verifier checks exact leaf ownership, retained typed transfers,
  branch-source identity, natural-loop identity, loop and local exit targets,
  local-region evidence, and every explicit loop-control or local-goto
  transfer. The real `early_return` tree now produces deterministic raw
  pre-pass pseudocode with a structured `if/else` and no goto. The real
  single-exit `dowhile_atleastonce` tree also renders as `do`/`while`, with its
  body exit recovered as `break` and no goto; the adapter requires a unique
  typed latch and exit before accepting that spelling. The top-level real
  `two_entry_loop` local-labelled tree now renders through the existing
  labelled-CFG fallback: every retained local goto resolves to an emitted
  label, exit paths and their verified terminal clones remain present, and no
  irreducible edge is hidden behind speculative structure. The real nested
  irreducible fixture now also renders its surrounding pre-tested loop while
  retaining the inner region's honest labelled transfers. The adapter accepts
  that spelling only when at least one typed loop break exists and every break
  reaches the lexical continuation; mismatched exits remain an explicit
  decline. A RED experiment on
  `loop_return_on_neg` confirmed that v1's one-distinguished-exit `While` could
  not encode its two exit-specific paths without reversing a branch or moving a
  verified terminal clone. The region/AST boundary now has an explicit
  `MultiExitLoop`: its body retains typed exit transfers, lowering materializes
  each independently verified exit region at that exact transfer, and the real
  fixture emits deterministic `while (1)` pseudocode with both return paths and
  no goto. The real gcc-O2 `duff_copy` tree now also renders its independently
  verified eight-way typed dispatch as `switch`/`case 0..7`, while locally
  degrading the suffix-entry irreducible loop to resolved labelled gotos; no
  indirect-jump placeholder survives. Repeated recovery produces the same tree
  and text. The 208-case gcc-O2 and 256-slot clang-O2
  `wide154_dense_effects` fixtures now prove the same typed-switch path scales
  beyond the small vertical slice without losing a case, and both emit
  deterministic parseable C. Multi-exit loops no longer
  require an invented common continuation: the gcc-O2
  `206_aarch64_wide_dispatch::dispatch_in_loop` shape independently owns its
  non-reconverging terminal exits. WP5 now preserves the guard's `al <= 6`
  proof through GCC's `movzbl al, eax`; the exact seven PIC-relative targets
  reach a switch nested inside that verified loop, including the case that
  exits to the shared return, with no indirect-jump placeholder. Every
  currently renderable real WP4 tree (`early_return`,
  `dowhile_atleastonce`, `loop_return_on_neg`, top-level `two_entry_loop`,
  nested `irreducible_inside_reducible`, `duff_copy`,
  `wide154_dense_effects`, and `dispatch_in_loop`)
  now also records deterministic parseable C derived from that same adapted AST
  by the shared source-level preparation pass; all eight texts pass a real host
  `cc -fsyntax-only` test. This is not yet the full production pass stack:
  pipeline-context comparison, execution, and a separately normalized CFG view
  remain open.
- [x] Keep `src/ir/structure/` as production authority until shadow evidence
  satisfies the promotion criteria.
- [~] Feed both structurers the same typed CFG and compare coverage, health,
  pseudocode, execution, GED, and runtime.
  `structure-v2-shadow` now feeds the existing `Cfg` directly into a
  deterministic condition-DAG observer and records exact block/edge coverage;
  verified flat regions and the first acyclic structured trees are also
  recorded, including reducible single- and multi-exit loops and locally
  labelled irreducible children. Verified acyclic trees additionally record
  deterministic raw pseudocode through the existing AST/printer pipeline;
  unsupported tree vocabularies retain `None` rather than speculative text.
  The first proven post-tested single-exit loop now renders through the same
  path. Verified top-level local-labelled trees now render honest, resolved
  gotos plus separately owned labelled definitions and exit paths. Verified
  multi-exit loops now render through the explicit region/AST node rather than
  selecting one distinguished exit. Each renderable RED fixture additionally
  records deterministic post-preparation parseable C and compiles under the host
  syntax gate. The nested-local fixture now renders a verified outer loop plus
  closed honest gotos for its inner irreducible region. Health, corpus-wide
  full-pipeline pseudocode, GED, and runtime comparisons remain. A current scoped
  production differential for
  `154_wide_switch:clang:O2:wide154_dense_effects` still reports the committed
  `fail`: v1 emits an unrecovered indirect jump even though the v2 shadow tree
  renders all 256 values. That committed v1 result remains the default-path
  baseline and is not v2 promotion evidence by itself.
  `prepare_llir_for_lowering_with_shadow` now closes the first pipeline-context
  gap without changing default selection: on explicit opt-in it adapts only an
  independently verified v2 tree into the same production `Region` boundary
  used by lowering. A real clang-O2 `wide154_dense_effects` test proves the
  production-prepared LLIR retains `case 0..255` and no indirect-jump
  placeholder. `decompile_many(..., style="decbench", shadow_v2=True)` now
  carries that verified region through the normal prototype, AST-pass, typed
  render, pre-render definedness, and execution-differential stages while the
  default remains v1. The first exact run exposed two real adapter/pipeline
  defects rather than being accepted as a crash: the guarded-switch owner block
  was lowered twice, and nested callee-save spills survived cleanup. Focused
  Rust tests now require the adapter to consume a separate switch-guard leaf
  exactly once. Machine-frame cleanup now exposes separate top-level and
  recursive scopes: every production caller retains the historical top-level
  proof, while only an independently selected shadow-v2 region opts into the
  recursive walk needed after structuring nests the prologue. The real clang-O2
  output has zero undefined reads and matches the original
  `wide154_dense_effects` on all 34 deterministic differential cases. This is
  one scoped execution cell, not the corpus-wide promotion comparison.
  The full def-use ratchet also exposed baseline drift predating this increment.
  Exact commit A/B testing showed `c7473267` soundly added two guarded
  `miniz_oxide::inflate::decompress` dispatch tables (25 and 4 arms), exposing
  40 latent reads in each Rust binary that embeds that runtime body; the new
  required `wide154_dense_effects` v1 cell separately contributes 32 reads.
  `defuse_baseline.json` now records those five guarded acceptances with their
  provenance. The six census assertions pass; none of those default-v1 debts is
  presented as a shadow-v2 improvement. A subsequent full-census run also
  caught a refactor error where the historical shallow candidate scan stopped
  seeing reads inside nested control flow; a focused Rust regression now pins
  that v1 liveness contract. After the repair, the census is green again.
  The host execution matrix additionally moved
  `42_rpn_evaluator:clang:O2:rpn_evaluate` from fail to pass. Its regenerated
  inventory removes two unrecovered rows (debug and stripped) but records the
  readability tradeoff honestly: each form grows from 3 to 12 gotos. This is a
  behavioural/coverage improvement, not evidence that v1 structuring improved.
  The first complete shadow coverage census now batches all 715 current
  structure rows across 436 objects. Shadow-v2 returned 247 candidates: 180
  reduced goto count, 38 tied, and 29 regressed; the remaining 468 declined
  locally without discarding supported siblings. Comparable goto totals fell
  from 2,166 to 1,570, while comparable rendered size grew 64.4%. This is
  rejection evidence rather than promotion evidence: the run used a native
  extension built alongside unrelated dirty shared-worktree changes, and the
  29 individual regressions plus 65.5% decline rate remain blockers. The exact
  command, provenance limit, timing, and next target families are recorded in
  `results/wp4-corpus-shadow-coverage.md`.
  The first regression-driven repair now preserves an immediate
  post-dominator when it equals the enclosing recovery boundary, preventing a
  nested arm from taking ownership of a shared continuation. Across previously
  comparable candidates this removed 100 aggregate gotos and 122,459 output
  bytes: 57 rows improved, 173 tied, and 17 worsened. It also made 21 declined
  rows renderable. Overall shadow coverage rose from 247 to 268 candidates,
  but 41 raw rows now regress, including repeated copies of one Rust runtime
  body. The repair is therefore landed evidence and improved output, not a
  promotion claim; clean pinned reruns and focused removal/refusal of the
  worsened cells remain open.
  The follow-up structured-fallthrough pass now removes only branch-final
  gotos whose exact lexical successor is their target label; loops, switches,
  exception regions, and intervening effects block the rewrite. Across all 268
  shadow candidates it made 41 rows better and none worse, removed 89 more
  gotos, and moved 22 regressions to ties plus two to improvements. The current
  exploratory census is therefore 219 improved / 32 unchanged / 17 regressed /
  447 declined. The report was still built from shared dirty native sources,
  so `results/wp4-corpus-shadow-coverage.md` retains the clean-pinned rerun as
  an explicit prerequisite rather than accepting these counts for promotion.
  Post-increment validation now has a complete green Rust gate (3,951 library
  tests plus every integration and doc-test target). The full Python gate is
  still red: it was stopped at 19% after 32 failures across current-master
  analyst, build-configuration, ARM32, and control-flow tests. Focused v2 tests
  and the no-worse corpus goto comparison are green, but they do not replace
  that broad red result.
  Switch suffix entries now have a faithful C spelling as stacked case and
  machine labels: a case whose entire body jumps into another arm's owned
  suffix no longer needs its entry `goto`, while ordinary branches to that
  same suffix retain the machine label. The 715-row exploratory census moved
  to 222 improved / 30 unchanged / 16 regressed / 447 declined, with aggregate
  shadow gotos falling from 1,434 to 1,006. The worst clang-O2 wide switch fell
  from 220 to 87 gotos, gcc-O0 fell from 219 to 63, and two defaultless
  fallthrough fixtures reached zero; all changed real outputs remain
  parseable. The run still used a shared dirty native build, so it is
  engineering evidence rather than promotion evidence. The remaining 16
  regressions, including the still-regressed clang-O2 and gcc-O2 wide-switch
  rows, remain explicit blockers.
  Duff's-device local regions are now placed inside their typed switch when at
  least two arms enter the same independently verified multi-entry region.
  The region remains single-owned and displaced fallthrough remains explicit.
  Both O0 rows moved from regressed to unchanged (clang 10 to 2 gotos, gcc 9
  to 1), and both gcc-O2 rows fell from 9 to 8 while remaining regressions. No
  other corpus row changed. The exploratory census is now 222 improved / 32
  unchanged / 14 regressed / 447 declined, with 988 comparable shadow gotos.
  Focused tests rule out the same-address self-loop found during development,
  retain exact tree verification, and compile the prepared real outputs.
  Bounded cleanup now also clones a short straight-line tail ending in return,
  rather than only one terminal block. The plan records every cloned block and
  independently verifies unique linear successors, terminal return identity,
  instruction counts, clone sites, and both per-tail and per-function budgets;
  local-labelled-region exits are excluded because they are separately owned
  definitions rather than tree-builder clone sites. The limits remain eight
  instructions and 64 total cloned instructions, with a new four-block cap.
  On the real gcc-O0 `hybrid_switch`, verified shadow output fell from four
  gotos to one, tying production while preserving the `20 + 5` path as an
  explicit labelled continuation. The 715-row exploratory release comparison
  moved to **230 improved / 30 unchanged / 12 regressed / 443 declined**, with
  980 comparable shadow gotos; no previously comparable row gained a goto.
  Four formerly declined rows also rendered, so totals and output bytes are not
  directly comparable with the preceding denominator. The native extension
  still included another lane's uncommitted parser changes, so these numbers
  remain engineering evidence, not promotion evidence.
  Switch recovery now stops every arm at a shared immediate post-dominator and
  owns that continuation once after the switch. Inside a natural loop, the
  join must remain within that same loop and cannot be its header; an enclosing
  loop exit remains owned by the loop. This converts case-final jumps into C
  `break` without moving or duplicating the shared effects. Real regressions
  cover both sides: clang-O0 `obfuscated_transform` proves a shared in-loop
  continuation moves after the switch, while clang-O2 `flattened_accumulate`
  proves an outer loop exit is not claimed as a switch join. The three clang-O0
  flattened functions and `obfuscated_transform` pass 34-case execution
  differentials. The complete exploratory comparison now reports **236
  improved / 30 unchanged / 6 regressed / 443 declined**, and comparable
  shadow gotos fell from 980 to 581. The two remaining clang-O2 wide rows fell
  from 87 to 54 gotos, and both gcc-O2 wide rows moved from regressed to
  improved (208 to 75 versus production's 203). No row declined or gained a
  goto relative to the preceding run. Shared dirty native provenance still
  prevents treating these totals as promotion evidence.
  Multi-exit materialization now also descends into recovered switch arms.
  Before this fix, both O0 `dispatch_in_loop` objects left their early-return
  case as a goto whose label repair placed an empty label after the function's
  final return; execution returned garbage for that path even though tree
  verification passed. A real GCC/Clang fixture regression now requires the
  case to contain its return path, and release execution differentials pass all
  34 deterministic cases for each compiler. The complete exploratory census
  is now **236 improved / 32 unchanged / 4 regressed / 443 declined** with 571
  comparable shadow gotos. Both O0 dispatch rows moved from regressed to
  unchanged, and no row declined or gained a goto.
  The four remaining regression rows are two debug/stripped pairs with
  different dispositions. GCC-O2 `duff_copy` recompiles and passes all 34
  execution cases; its eight shadow gotos are verified suffix entries into the
  recovered Duff body, while production reports four only by leaving the
  indirect dispatch unrecovered. An initial attempt to spell the 22
  clang-O2 `wide154_dense_effects` switch-join transfers as `break` ran before
  copy/fallthrough preparation and failed execution differential, so it was
  rejected. The accepted implementation performs the same adjacency-proved
  rewrite as the final semantic AST pass, after every consumer that could
  reinterpret `Break`. All 34 execution cases pass; clang-O2 falls from 54 to
  32 gotos and gcc-O0 falls from 22 to zero. Across the complete comparison,
  shadow gotos fall from 571 to **505**, with no new decline or status
  regression. The remaining wide gotos are suffix/shared-effect entries rather
  than transfers to the switch continuation.
  The comparison report now preserves those four raw `regressed` statuses and
  records a separate, fail-closed classification. Only the exact reviewed
  debug/stripped rows can match; each candidate must still contain a recovered
  switch, at least one direct goto, and a definition for every goto target.
  The pinned `ca91dc68` full run reports **4 accepted honest-goto rows / 0
  unexplained regressions**, alongside the unchanged raw **236 improved / 32
  unchanged / 4 regressed / 443 declined** counts. This closes classification,
  not WP4 promotion: execution, accounting, GED, structure-axis, and budget
  evidence below remain required.
  The ordinary execution-differential harness now accepts an explicit
  `shadow_v2` selection without changing its production default, including
  batched roots and recursively included local helpers. The pinned `6175d67d`
  comparison executes every one of the 272 rendered candidates from the same
  revision through identical fixture contracts and vectors. It reports **14
  improved / 175 stable pass / 23 stable non-pass / 21 regressed / 39 not
  executable**, with zero infrastructure findings. The 39 are internal/static
  functions absent from the dynamic ABI and remain visible rather than being
  mislabeled as missing. Eight function families account for all 21 semantic
  regressions: branch hints, flattened accumulation, returning switch arms,
  Base64, bitset selection, bisection square root, internal rate of return, and
  trie insertion. Seven families improve. This is the first corpus-wide
  execution result and is a promotion blocker, not an accepted trade-off.
  The first correctness repair at `0da8744d` stops treating a back-edge as an
  implicit loop continuation merely because it is final inside a nested
  conditional or switch arm. Only the true outermost final transfer may fall
  through; nested transfers remain explicit, resolved gotos. This removes 15
  of the 21 behavioral regressions: the pinned rerun reports **14 improved /
  190 stable pass / 23 stable non-pass / 6 regressed / 39 not executable**, with
  zero infrastructure findings. The remaining six cells are three families:
  clang-O2 branch hints, flattened accumulation, and Base64 (including their
  stripped twins where present). Correctness exposes a readability debt:
  shadow gotos rise from 505 to 773 and 13 raw structural rows become
  unexplained regressions. Source-level `continue` recovery or an equally
  proved spelling is required before those transfers can be called structurally
  closed.
  Source-level continuation recovery at `85a61693` removed those unexplained
  structural regressions while retaining zero execution regressions. The
  follow-up at `80f5d106` now preserves ordinary nested conditionals inside
  post-tested loops rather than flattening or declining them. Its release-built
  pinned comparison covers 715 functions: 262 improve, 68 tie, four exact
  reviewed honest-goto rows remain raw regressions, 381 decline, and no
  regression is unexplained. The corresponding 334-candidate execution
  comparison reports 14 improvements, 246 stable passes, 29 stable non-passes,
  45 explicitly non-executable candidates, zero regressions, and zero
  infrastructure findings. The complete Rust gate is green and the global
  Python gate terminated red. Exact commands, timing, RSS, denominator limits,
  and validation boundaries are in
  `results/wp4-nested-post-tested-rendering.md`.

### RED fixtures

- [x] `01_conditional_polarity.c::sc_mixed`: condition DAG. The checked-in
  gcc-O0 binary is discovered, lifted, converted to SSA, and observed with
  total block/edge coverage; the synthetic equivalent is also checked against
  all eight Boolean valuations of `(a && b) || c`.
- [x] `03_loop_shapes.c::dowhile_atleastonce`: rotated multi-exit loop. The
  real gcc-O0 fixture yields a post-tested natural loop with explicit latch,
  `Continue`, and exit `Break` facts.
- [x] `03_loop_shapes.c::loop_return_on_neg`: shared terminal tail. The real
  gcc-O0 fixture preserves distinct loop exits converging on one return block,
  which remains singly owned.
- [x] Existing irreducible/dispatch fixtures for honest local goto behavior.
  The real `211_irreducible_loops` `two_entry_loop` and nested-irreducible
  functions preserve verified local labelled transfers; the nested case also
  proves that the surrounding natural loop survives.
- [x] A synthetic irreducible CFG whose correct result necessarily retains a
  goto, recorded as `accepted_honest_goto`.
- [x] Extend `tools/gen_structural_baseline.py` and
  `python/tests/test_decompiler_fixture_structural.py` for that classification.
  Every accepted row must name a reproducible CFG property; free-form waivers
  are invalid. The closed manifest contract names
  `irreducible_scc_multiple_entries_no_dominating_header`, the Rust fixture test
  reproduces it, and the structural report records only lanes that actually
  contain a goto.

### Safety properties

- [x] Every emitted-candidate input block appears exactly once or has an explicit duplicated-tail
  provenance record.
- [x] Every emitted-candidate CFG edge is represented by structured control, a local goto, or a
  typed refusal.
  `verify.rs` independently compares candidate ownership, terminals, edge
  multiplicity, polarity, and `Break`/`Continue` classification with the typed
  CFG. Accepted irreducible SCCs become local labelled regions; unclassified
  residual cycles still return `CyclicGraph` with zero claimed coverage.
- [x] Local failure cannot collapse an otherwise structured function. The real
  nested-irreducible fixture retains its outer natural loop while only the
  inner multi-entry SCC degrades to local gotos.
- [~] Tail duplication is size-bounded and restricted to straight-line return
  tails. Shadow cleanup keeps one deterministic canonical predecessor and
  records the complete block chain, source/predecessor identities, and total
  instruction count. Independent verification rejects repeated blocks,
  non-linear edges, a non-return terminal, forged counts or clone sites, and
  any plan above four blocks, eight instructions per tail, or 64 cloned
  instructions per function. Clone sites inside separately owned local-labelled
  regions are excluded. Synthetic single- and two-block boundary tests,
  branching-tail refusal, forged non-linear provenance, the real
  `loop_return_on_neg` shared return, and the real gcc-O0 `hybrid_switch` are
  green. Each planned clone is materialized as an explicit `DuplicatedReturn`
  carrying its whole chain; the tree verifier rejects missing, altered, or
  invented materializations one-for-one against the checked plan. Promotion
  still requires clean-pinned corpus and execution evidence.
- [x] Condition simplification preserves machine-width predicate semantics.
  Each shadow condition atom now carries the SSA producer's exact `CmpOp`,
  recoverable operand width, and `CondJump` inversion; unavailable producer or
  width evidence remains explicit `None`. Boolean complement folding compares
  the complete typed atom. Boundary tests prove that exact complements fold,
  while 32/64-bit or signed/unsigned mismatches do not.

### Promotion criteria

- [~] No execution-differential regressions. The fail-closed corpus route is
  now implemented. The first pinned run at `6175d67d` exposed 21 regressions;
  `0da8744d` removed 15. `c3bbe2a6` repairs or locally declines the remaining
  unsafe shapes, and its pinned 250-candidate report records **zero
  regressions**, 12 improvements, and no infrastructure findings. Thirty-nine
  candidates remain explicitly non-executable, so broader coverage remains
  open. The expanded pinned `80f5d106` report remains at zero regressions over
  334 candidates after enabling nested post-tested branches; 45 candidates are
  explicitly non-executable. See `results/wp4-nested-control-safety.md` and
  `results/wp4-nested-post-tested-rendering.md`.
- [ ] No unexplained block/edge accounting findings.
- [ ] GED does not regress on the pinned sample.
- [ ] The structure axis improves after accepted honest gotos are separated.
- [ ] Runtime and output-size budgets are recorded and accepted.
- [ ] Only then make v2 default and selectively retire compensation passes.

## 11. WP5 — Typed indirect targets and switch recovery

Purpose: eliminate the 48 unrecovered dispatch rows and give the structurer
one authoritative set of case edges.

### Production changes

- [~] Extend indirect-target analysis with bounded value-set analysis for:
  comparison guards, masks, subtract-and-unsigned-compare ranges,
  PIC-relative tables, and absolute tables.
  The current implementation already lives primarily in
  `src/analysis/dispatch.rs`, `src/analysis/cfg/dispatch_resolution.rs`, and
  `src/analysis/jump_table.rs`, rather than the relocation-only
  `src/ir/indirect_targets.rs`. It carries comparison, stack/memory, mask, and
  rebased bounds into bounded PIC-relative and absolute decoders. The live
  gcc-O2 Duff fixture proves that `arg2 & 7` resolves exactly eight ordered
  targets. Chained x86 unsigned guards now retain their exact edge-local
  strictness: `ja`/`jnbe` admit equality, while `jae`/`jnb` reduce the
  fallthrough maximum by one. The real Clang O2 fixture-204 guard therefore
  resolves its exact seven-entry adjacent table rather than over-reading an
  eighth slot. The remaining encodings and measured declines still need a
  fresh census.
- [~] Add target-specific decoding for ARM `tbb`/`tbh` and
  `ldr pc, [pc, r0, lsl #2]` through the relevant lifter/machine-model layer.
  Both forms already decode through `dispatch_resolution.rs`; the remaining
  work is to complete the architecture lanes and consolidate the evidence
  contract. AArch64's GCC O2 compact signed-byte form is now also decoded:
  W/X register identity and the taken-edge `b.ls` bound prove the selector and
  extent, while exact `LDRB` plus encoded `ADD ..., SXTB #2` evidence proves
  the table and target base. Checked decoding rejects malformed,
  non-executable, overlapping, or wrongly scaled candidates. This is the
  bounded `310b949e` slice, not general AArch64 dispatch completion.
- [x] Represent resolved case values, targets, default edge, provenance,
  bounds, and completeness as typed evidence derived from `Op::IndirectJump`
  and its typed CFG edges.
  `Op::IndirectJump.index`, typed CFG `SwitchCase`/`SwitchDefault` edges, and
  ordered `Cfg::case_labels` already carry the first production facts. WP4's
  independently verified `RegionCandidate` now receives explicit
  `SwitchEvidence` and `SwitchDefaultEvidence` without re-recognising output:
  the real `102_duffs_device-gcc-O2.so::duff_copy` fixture records one dispatch,
  eight ordered values `0..7`, and its linked bypass edge. The verified WP4
  tree now consumes that same evidence and renders an eight-arm switch with
  honest labelled transfers into the suffix-entry region. At `9ad9414d`, the
  shared immutable `SwitchEvidence` is built once by `Cfg` from typed
  `SwitchCase`/`SwitchDefault` edges plus ordered labels, and production and v2
  consume it. Completeness fails closed on missing or empty labels, ambiguous
  defaults, and incomplete evidence; v2 declines before recovery or rendering.
  The verifier remains independent and checks edge/label/default relationships,
  including rejection of forged missing labels and deletion of a proven
  default.
- [~] Make discovery, `src/ir/structure_accounting.rs`, both structurers, and
  rendering consume the same evidence object. Both structurers now share the
  immutable typed object and rendering receives their structured result.
  Structure accounting and the independent verifier intentionally retain
  separate relational checks rather than accepting producer assertions. The
  remaining corpus-wide accounting and decline evidence is still open.
- [ ] Add `Op::Switch` only if it becomes the sole semantic owner of those
  targets and receives execution semantics.

### Tests

- [ ] Keep WP0's strict xfail for the constant-false Duff's-device latch RED
  until the semantic fix lands here.
- [~] Focused fixture coverage for `102`, `103`, `145`, `154`, `206`, and
  `215`, across applicable O0/O2 and architecture lanes.
  The real `102` gcc-O2 discovery-to-shadow vertical slice is green. The gcc-O2
  `154` side-effect switch preserves all 208 typed case values through verified
  deterministic C rendering. The clang-O2 `154::wide154_dense_effects` lane
  now treats `movzbl`'s 8-bit source width as an intrinsic `0..255` proof,
  resolves all 256 table slots at site `0x15d9`, and records no unresolved
  decline for that site. All 256 values reach the independently verified shadow
  tree and deterministic parseable C without an indirect-jump placeholder;
  scoped execution-differential coverage is now green for this clang-O2 cell,
  while the remaining fixture/compiler matrix remains open. The gcc-O2
  `206::dispatch_in_loop` lane now
  preserves a guarded byte selector through register zero-extension, decodes
  exact cases `0..6`, and renders that typed switch inside its verified loop.
  The pinned clang-14 `statemachine::fsm` lane now carries the already-resolved
  four-way dispatch through the ordinary structurer as a dense guarded switch
  inside `do ... while`. Its guard-only default goes to the proven latch, and
  its terminating case borrows the shared return epilogue without taking global
  ownership. The former strict xfail is green with no goto or indirect-jump
  placeholder.
  The Clang O2 `204::adt204_guarded_control` lane now also reaches the ordinary
  production structurer as cases `0..6` plus the out-of-table default, with no
  indirect-jump placeholder. Acceptance requires SSA-transitive dependence on
  an unsigned comparison, rather than treating every nearby conditional as a
  range guard. All 20 fixture-204 cells pass. The complete 838-lane comparison
  has no regression attributable to this increment; its one reported
  `rust_slice_get` regression reproduces identically at clean `55ab688b`, and
  the remaining 34 movements are older unrecorded improvements.
  Structure accounting is now clean for this real fixture. The shared return
  tail is an explicit borrowed rendering with one underlying structural owner,
  so neither `EdgeUnaccounted` nor `BlockDuplicated` remains. The full-matrix
  `152_deep_nesting` canary proves predecessor-specific return values were not
  traded away for cleaner accounting.
  The AArch64 GCC O2 `206::dense_dispatch` lane now recovers its compact
  signed-byte branch table as cases `0..15` plus default and passes all 22
  deterministic execution cases. Ten adjacent AArch64 switch lanes report no
  regression after the single reviewed baseline movement. The complete
  412-lane AArch64 O0/O2 comparison has no attributable regression: all four
  reported regressions reproduce identically at parent `7c0ba967`.
  Its whole Python gate is complete but red: seven of eight apparent new
  failures pass on immediate focused retry, and the one deterministic delta is
  the expected six-test census increase now recorded at `88bb8650`. Other
  compiler/optimization and named fixture lanes remain.
  GCC i386 O2's GOT-relative table form is also recovered. Eight cells now
  pass execution, table address and target base remain distinct typed facts,
  and all four regressions in the complete 410-lane comparison reproduce at
  the parent. Its exact-checkout whole Python gate has no tip-only failing node
  IDs and remains broadly red at 4,597 passed and 125 failed.
  GCC ARMv7 A32 O2's compact unsigned-byte form is now recovered from exact
  PC-relative literal materialisation through the scaled PC terminal. Nine
  function verdicts improve and none decline across the complete 410-lane,
  1,604-function parent/tip comparison. `dense_dispatch` passes production
  execution; `dispatch_in_loop` passes both shadow-v2 and, after `6f0ba701`,
  production-v1 execution. Its multi-latch raw loop owns every backedge and
  initially left one explicit outer-guard transfer as a quality-only accounting
  finding. The bounded private-prefix/shared-terminal repair at `0e29ffc4`
  closes that finding, while `28b3bc5b` removes the adjacent unreachable
  undefined select arm. A graph-sized recursive work budget also makes four
  valid 48-entry tables degrade to complete labelled CFG output rather than
  overflowing the native stack.
- [x] Unit tests for malformed, out-of-range, overlapping, and truncated
  tables; analysis must decline safely.
- [~] Execution differential for every newly recovered switch. The explicit
  shadow-output path now runs the exact typed C returned by
  `decompile_many(..., shadow_v2=True)` through the ordinary fixture comparator.
  The clang-O2 `154::wide154_dense_effects` cell passes all 34 deterministic
  cases with zero pre-render undefined reads. The default v1 path remains its
  committed `fail`. Both GCC-O0 and clang-O0 `206::dispatch_in_loop` cells now
  also pass all 34 cases after a switch-arm loop-exit materialization regression
  was found and fixed; every other newly recovered switch cell still needs the
  same explicit execution evidence before WP5 can complete. The pinned
  clang-14 `statemachine::fsm` default-v1 path now also recompiles and matches
  the original across 64 deterministic fuzz inputs. The Clang O2
  `204::adt204_guarded_control` now passes all 34 deterministic cases through
  both the independently verified shadow-v2 path and the production default
  path. Its production baseline is updated from `fail` to `pass` after the full
  838-lane comparison and an isolated old-tip A/B proved its sole reported
  regression predates this increment.
  The pinned GCC O0 `statemachine::fsm` decision tree is now recovered as the
  exact dense `switch (st)` with cases `0..3`. The matcher accepts GCC's nested
  `st != 0` terminal partition and the exact sign-preserving typed relational
  views produced by late comparison folding; it rejects side effects, a second
  discriminant, duplicate cases, and ambiguous case-label ownership. Production
  output drops from 13 gotos to 4 (the remaining four encode the still-unowned
  counted loop and two case-local assignment joins), recompiles, and matches the
  original across the deterministic differential test. The former strict xfail
  is now an ordinary required regression test; loop ownership remains separate
  WP4 cleanup rather than a prerequisite for recovering the source switch.
- [~] Structural census assertion that typed cases reach the structurer.
  One real per-function assertion now proves the exact ordered cases and
  default reach the shadow tree, its independent verifier, and deterministic
  parseable C rendering. Corpus-wide census coverage remains.

### Implementation evidence — 2026-09-03 malformed-table safety

The bounded relative decoder and whole-section scanner previously computed
`table_va + signed_offset` through wrapping integer arithmetic. At either edge
of the address space, malformed table bytes could therefore wrap into an
address accepted by the executable-region predicate and manufacture a switch
target. Two RED tests reproduced both directions: `u64::MAX - 7 + 16` was
accepted as target `8`, and `4 + (-16)` was accepted near `u64::MAX`.

`src/analysis/jump_table.rs` now uses checked signed address arithmetic. The
bounded decoder reports the existing typed
`TableDecline::TargetArithmeticOverflow { index }`; the heuristic scanner
terminates the candidate run. Explicit unit coverage now includes malformed
object bytes, a table extent truncated at both the section end and a non-zero
offset, a target overlapping the absolute table itself, a non-executable
relative target, adjacent tables, and both arithmetic boundaries.

Validation against the working tree and a fresh release extension:

- `cargo test --features python-ext analysis::jump_table::tests -- --nocapture`:
  18 passed, 0 failed;
- `cargo test --features python-ext`: all 3,089 library tests and every ordinary
  integration target passed; its final CFR doctest hit a transient duplicate
  `pyo3` artifact error, then
  `cargo test --features python-ext --doc identity::cfr` passed 1/1 in
  isolation;
- the six named WP5 fixture families selected 24 baseline lanes with no scoped
  regressions; one `206_aarch64_wide_dispatch:gcc:O2:dispatch_in_loop`
  improvement was visible but is not attributed to this address-boundary fix
  in the concurrent worktree; and
- `08_indirect_dispatch` across i386, ARMv7, AArch64, and x86-64 GCC 15 selected
  eight architecture lanes with no scoped regressions.

The def-use census passed its five safety checks and stopped at the improvement
ratchet because concurrent work removed many baseline violations; it requires
a separately reviewed baseline refresh. The corpus-wide structural command was
still running when this evidence was written and is not claimed green here.

### Exit criteria

- [ ] `unrecovered` switch/dispatch rows reach zero or have typed, triaged
  declines with a specific unsupported encoding.
- [ ] No target exists in discovery but disappears before structuring.
- [ ] The Duff's-device latch is semantically correct.

## 12. WP6 — Constraint-based C type recovery

Purpose: replace sticky, flow-insensitive type joins with explicit constraints
while keeping machine width as truth.

### Production changes

- [ ] Introduce a type-constraint layer under `src/ir/types_recover/`:
  - new `constraints.rs`: equality, width, signed-use, pointer, pointee,
    aggregate, ABI, load/store, and call constraints;
  - new `solver.rs`: deterministic solution and conflict reporting;
  - new `confidence.rs`: provenance and confidence ordering;
  - retain `TypeHint` adapters until all consumers migrate.
- [ ] Treat signedness as per-use evidence, not an irreversible value property.
- [ ] Treat unsigned range comparisons as range facts.
- [ ] Add recursive pointer and aggregate representations needed by `char **`,
  by-value structs, and hidden returns.
- [ ] Key type facts by stable value identity from WP3.
- [ ] Split generated type/return reports by C vs Rust before judging movement.

The first incremental constraint slice landed in
`src/ir/types_recover/constraints.rs` on 2026-09-04. It records signed and
unsigned interpretations against exact operand uses in deterministic order,
resolves only unanimous evidence, and keeps equality, address indexing, and
x86's implicit 32-to-64-bit register-write extension neutral. The compatibility
`TypeHint` adapter now consumes that result only at the ABI live-in boundary;
the flow-insensitive register map continues to provide class and machine width.
This starts, but does not complete, the production checkboxes above: pointer,
aggregate, call, confidence, and general solver constraints remain open.

### Required `classify` signed-loop vertical slice

The exact source shape below is a required WP6/WP7 cross-package regression,
not an illustrative snippet:

```c
int classify(int n) {
    if (n < 0) return -1;
    while (n > 100) { n -= 100; }
    return n;
}
```

It was compiled locally at `80f5d106` with GCC and Clang at O0 and O2. The
release decompiler recovers balanced, parseable `if`/`else` plus `while`
control at O0. With DWARF it now renders the authoritative
`int classify(int n)` declaration, but the body still leaks unsigned casts.
After `strip --strip-debug`, both O0 compilers regress the return declaration to
`unsigned int`, and the negative result renders as `0xffffffff` or an explicit
unsigned cast. This is a missing stripped-inference capability, not a WP8
declaration-authority defect.

Required WP6 features:

- [~] Record negative return constants and signed relational uses as exact,
  per-use return/value constraints without making signedness sticky globally.
- [x] Resolve a stripped 32-bit return as signed only when all width-bearing
  ABI evidence agrees and the signed evidence is unopposed; retain ambiguity
  when signed and unsigned uses conflict.
- [x] Propagate the selected return interpretation to return expressions so an
  authoritative signed declaration does not retain redundant unsigned casts.
- [~] Keep genuinely unsigned functions unchanged and preserve C/Rust-separated
  measurement totals.
- [x] Add the fixture as GCC/Clang O0 debug and stripped cells. Keep O2 as a
  separately reported observation: compiler strength reduction or unrolling
  may erase the source loop, so exact loop reconstruction is not an O2
  correctness requirement.

Implementation boundaries for the remaining return-type work:

- Extend `src/ir/types_recover/result_hint.rs` (and the incremental constraint
  layer under `src/ir/types_recover/`) to collect return-width, signed-use, and
  negative-constant evidence. ABI-mandated x86-64 zero-extension of a 32-bit
  result is transport evidence, not proof that the C result is unsigned.
- Make `src/ir/ast/return_ctype.rs` consume the resolved result interpretation
  when choosing the declaration and simplifying each return expression. It may
  remove an unsigned cast only when that cast is an ABI transport shell over a
  value proved signed at the same source width.
- Keep `src/ir/const_fold.rs` responsible only for the already-landed terminal
  predicate equivalence. Do not infer a function return type from the visual
  shape of that folded predicate or from rendered variable names.
- On conflicting or incomplete evidence, preserve the current unsigned or
  ambiguous spelling rather than guessing. This vertical slice must remain an
  incremental consumer of the future WP6 solver, not establish a second type
  system in the AST renderer.

#### `classify` issue-to-feature contract

This table is the authoritative scope for the reported example. It keeps the
visible defects tied to production capabilities and prevents a prettier single
render from being mistaken for completion.

| observed behavior | classification | required production feature | acceptance evidence |
|---|---|---|---|
| The recovered `if`/`else` and `while` match the source control shape. | Existing strength to preserve. | Keep the WP4 structured loop and branch result unchanged while expression and type passes improve it. | Structural fixture remains an `if` with a nested `while`; execution differential remains green. |
| `n > 100` renders as the expanded `((x == 100) \| (x <s 100)) == 0` flag formula. | Glaurung expression-normalization defect. | Add a width- and signedness-proved terminal comparison fusion for the exact shared value and constant; carry its signed result type and decline every ambiguous variant. | O0 GCC and Clang, debug and stripped, render `n > 100` or `100 < n`; expanded flag spelling is absent; proof and refusal tests below pass. |
| A stripped build renders `unsigned int classify(...)`. | Glaurung stripped type-inference limitation. | Combine negative return constants, signed relational uses, ABI width, and per-use constraints; select signed only with unopposed evidence. | Both stripped O0 compiler cells render a signed 32-bit return, while genuinely unsigned counterexamples remain unsigned. |
| The negative return renders as `0xffffffff` and signed bodies retain unsigned casts. | Consequence of missing signed return propagation and destination-typed cleanup. | Propagate the chosen signed return interpretation into return-expression rendering and remove only provably redundant casts. | Render `return -1;`; emitted C compiles and boundary execution agrees with the reference. |
| A pasted output appeared to contain an unmatched brace. | Not reproduced in the pinned local rendering; likely transcript truncation, not a confirmed product defect. | Do not create a speculative brace-repair pass. Retain parseability and delimiter balance as gates on every affected cell. | Host C syntax check succeeds for debug and stripped outputs from both compilers. |

Completion means all four GCC/Clang O0 debug/stripped cells satisfy the table
in one pinned release build. An isolated constant-fold unit test or one
debug-assisted signature is necessary evidence, but is not completion.

The bounded return-result implementation is now green in all four required
signed cells and all four genuinely unsigned control cells. It joins exact SSA
result definitions before rendering, treats all-ones as ambiguous without
independent evidence, and removes only declaration-consistent ABI transport
casts. This closes the concrete `classify` return issue, but not WP6's general
constraint solver or corpus-wide C/Rust measurement exit criteria. See
`results/wp6-classify-signed-return.md`.

The follow-on `2be036eb` typed-render increment removes the remaining
`(long)(n)` shells from both signed `classify` predicates. It consults the
selected declaration, accepts only value-preserving signed widening against a
representable literal, and retains wider-literal and unsigned cases. This
closes the concrete example's cast-heavy predicate spelling without claiming
the general WP6 constraint solver is complete.

The bounded fixture-215 follow-on at `a88edd9a`/`8ab39b50` handles the inverse
boundary conflict: an authoritative `uint64_t` parameter consumed by a signed
machine comparison in Clang O2's partition tree. `DeclarationPlan` preserves
the source signature and records that its integer fact is authoritative; the
renderer applies a same-width signed cast only at that exact relational use.
The initially broader rule over all inferred unsigned declarations was rejected
after the structural census exposed unnecessary churn. The narrowed tip makes
`wide_selector_high_labels` pass `UINT64_MAX`, moves the final Clang-O2
fixture-215 cell from fail to pass, and produces byte-identical matched
parent/tip structural and def-use diagnostics. This is a concrete per-use WP6
increment, not the general solver. See
`results/wp6-authoritative-unsigned-signed-edge.md`.

Required regression coverage is equally part of completion:

- `python/tests/test_classify_signed_loop.py` must assert the signed declaration,
  simplified relational condition, `return -1;`, absence of the redundant
  unsigned return cast, balanced/parseable output, and boundary execution for
  every O0 compiler/debug cell.
- `tests/fixtures/classify_signed_loop.c` must include a genuinely unsigned
  control (unsigned parameter/result and unsigned relational use). Its stripped
  GCC and Clang outputs must remain unsigned.
- Focused `src/ir/ast/return_ctype.rs` tests must cover signed resolution,
  unsigned preservation, conflicting evidence, and same-width ABI-cast removal;
  mismatched widths and non-transport casts must be refusal cases.
- The scoped loops/polarity/switch/width corpus and the full required Rust and
  Python gates must be reported separately. Syntax success alone does not prove
  the return-type inference or execution behavior correct.

### Tests

- [x] RED `tail_dispatch` signedness and return-width case.
- [ ] Existing `python/tests/test_pdb_type_recovery.py` xfails.
- [~] Existing aggregate/return fixtures `195`, `197`, and `198`. Commit
  `ede20fb0` repairs three SysV AMD64 memory-class return lanes by combining
  adjacent hidden-result setup with proved caller live-ins and promoting the
  declared result extent as one stack aggregate. Commits `9fed7199` and
  `41af392d` then preserve register-resident INTEGER+SSE results and stop the
  differential oracle from comparing indeterminate aggregate padding. Fixtures
  `195` and `198` are now entirely pass or intentionally structural across the
  scoped host matrix. Commits `cf9160ba`, `fe50a360`, `3f4f12fe`, and
  `db750dbc` close all nine former O2 HFA failures in `197`: declared
  `xmm0:xmm1` results are materialized all-or-nothing, exact direct-call
  contracts permit clobber-free pair forwarding, bounded legacy packed-XMM
  instructions retain their lane semantics, packed dword concatenation widens
  before shifting, and proved aggregate materialization prevents cross-bank
  scratch identities from collapsing into one cosmetic return name. The full
  four-lane fixture now has every non-structural row passing. See
  `results/wp6-sysv-hidden-return-buffers.md` and
  `results/wp6-sysv-split-bank-returns.md` and
  `results/wp6-sysv-sse-pair-returns.md`.
- [x] `python/tests/test_decompiler_observable_parameter_width.py`.
- [x] Stripped-lane tests to prove improvements do not depend on debug types.
- [ ] Solver unit tests for conflicts, ambiguity, and deterministic ordering.

### Exit criteria

- [ ] C parameter and return axes improve without stripped regressions.
- [ ] Low-confidence signedness is rendered honestly rather than asserted.
- [ ] Rust numbers remain visible but do not block C milestones.

The checked test slice is bounded evidence, not WP6 completion. Both stripped
GCC and Clang `tail_dispatch` declarations changed from
`unsigned int, unsigned int, int` to `int, int, int`; the inferred debug
prototype now agrees with the authoritative DWARF declaration and no longer
emits a false conflict. The complete O0/O2 execution corpus remained at 824 of
838 passing lanes with no scoped regressions and 27 pre-existing baseline
improvements. See `results/wp6-per-use-signedness.md` for commands and limits.

## 13. WP7 — Width-proved expression idioms

Purpose: translate compiler idioms into source-like expressions only when the
machine-width equivalence is established.

### WP7A — Immediate render-level idioms (depends on WP0)

- [x] Implement destination-typed literal spelling at the existing typed
  render boundary so `-1` in `int32_t` does not render as `0xffffffff`.
- [x] Implement one width-preserving subtract-and-unsigned-compare range fusion
  beside the existing `cmp_fusion` boundary.
- [x] Keep both changes narrow, table-driven where practical, and independently
  revertible. Do not introduce a second value-identity system.

Implementation revision: `81ffe9ab`. The literal rule consumes the existing
destination type only and declines unknown, unsigned, pointer, boolean, and
64-bit-positive cases. The range rule consumes the existing `TypeMap` or an
explicit unsigned cast shell, preserves that exact 8/16/32/64-bit view on both
replacement comparisons, recognizes both `Sub(x, low)` and the folded
`Add(x, -low)` form, and declines wrapping intervals. No new value identity or
name-parsing convention was introduced.

### WP7B — SSA-expression idioms (depends on WP3)

- [ ] Add an SSA-expression idiom module, preferably `src/ir/ssa_idioms/`,
  after WP3 establishes the owning SSA boundary.
- [~] Land one rule per increment:
  1. [x] flag-derived relational normalization, beginning with the exact typed
     equivalence `!((x == k) || (x <s k)) == (x >s k)` seen in `classify`;
  2. [x] bounded cdecl32 high/low borrow normalization for an authoritative
     unsigned 64-bit source and an immutable, single-definition alias chain;
  3. [ ] strength-reduced constant multiplication;
  4. [ ] signed division/modulo by a power of two;
  5. [ ] compiler magic-number division;
  6. [ ] compound boolean-mask normalization;
- [ ] Each rule must declare operand width, signed interpretation,
  preconditions, output type, and origin composition.
- [ ] Never peel or narrow casts unless equivalence is proved at the original
  width.
- [ ] Permit the first relational rule at the existing typed comparison-fusion
  boundary before WP3 only if both comparisons already carry the same exact
  SSA value, constant, width, and signed relation. Otherwise decline until WP3
  supplies stable identity; do not compare display names.

### Tests

- [x] Exhaustive equivalence at 8 and 16 bits.
- [x] Boundary-complete plus seeded randomized equivalence at 32 and 64 bits.
- [x] Regression test for the earlier `cmp_fusion` 64-to-32 narrowing bug.
- [x] End-to-end fixtures from `03_loop_shapes` and `102_duffs_device`.
- [x] Execution differential and pinned byte/readability measurements.
- [x] Exhaustively prove the `classify` relational rule at 8 and 16 bits and
  use boundary-complete plus seeded randomized checks at 32 and 64 bits.
- [x] Require exact refusal for mixed widths, unsigned `<`, different values or
  constants, inverted polarity mismatch, and a comparison with missing
  producer evidence.
- [x] End-to-end `classify` tests must require `while (n > 100)` (allowing
  equivalent operand order), reject the expanded `ZF | (SF ^ OF)` spelling,
  compile the emitted C, and pass execution differentials on negative, 0, 100,
  101, repeated-subtraction, and integer-boundary inputs.

The first relational rule landed at `9c9c607c` in the existing terminal
constant-fold boundary under the pre-WP3 exception above. It requires the same
expression, constant, source width, outer width, signed `<`, unsigned equality
view, non-negative signed-representable constant, and equality-to-zero terminal
use. Ten focused proof/refusal tests pass. The release-built GCC/Clang O0 debug
and stripped fixture cells all emit `100 < n` through the preserved signed
view, compile as C, and pass 34 differential cases each. The 24-lane loops,
polarity, switch, and width corpus reports zero scoped regressions. This closes
the predicate subproblem only; stripped return inference and redundant return
casts remain WP6 work. See `results/wp7b-classify-signed-predicate.md`.

The bounded two-word range rule landed at `f39bdf0e`. It recognizes only the
exact cdecl32 identity `(0 <u hi) | ((0 - hi) <u (k <u lo))`, requires `hi` and
`lo` to be the unsigned 32-bit projections of the same recovered unsigned
eight-byte source, and resolves only single-definition aliases whose complete
dependency set is never assigned. A following path rule removes the repeated
inverse nested guard only after ordinary boolean folding makes both typed
comparisons structurally complementary. This is an explicit pre-WP3 range-
fusion exception, not the general SSA-expression framework; mutable or
ambiguous identities decline. The real i386 O2 output replaces the flag tree
with `op <= 5` and removes the impossible nested arm, while retaining the
honest unrecovered indirect jump and red execution status. See
`results/wp7-cdecl32-wide-range-predicate.md`.

At `81ffe9ab`, `cargo test --features python-ext` passes, including 15 focused
comparison-fusion tests and 191 AST/render tests; the six def-use census tests
also pass. The required real-binary slice runs 72/72 `03_loop_shapes`
functions successfully across clang/gcc O0/O2, retains the four independently
known `102_duffs_device` failures, and reports zero scoped regressions. In the
real gcc-O2 Duff output, the 84-byte opaque predicate
`(unsigned)15 < (unsigned)(arg2 - 1)` becomes the 159-byte explicit predicate
`(unsigned)arg2 < 1 || 16 < (unsigned)arg2`: bytes increase by 75, but the
accepted interval and rejection reason are directly readable. This is a
readability improvement, not an execution or aggregate-score improvement; the
unrecovered Duff indirect jump remains the reason that cell fails.

### Exit criteria

- [x] Every enabled WP7A rule has a machine-width equivalence test. WP7B is not
  yet enabled.
- [x] No execution regression and no unexplained type-width change in the
  required WP7A fixture slice.
- [x] The pinned Duff measurement improves readability with an explicitly
  recorded 75-byte cost; neither rule is claimed as an aggregate score win.

## 14. WP8 — Declaration authority and conflict provenance

Purpose: ensure analyst, DWARF, and PDB declarations improve rendered output
without concealing inference disagreement.

### Production changes

- [x] Trace `tail_dispatch` through:
  `src/python_bindings/ir/dwarf_contracts.rs`,
  `src/python_bindings/ir/type_maps.rs`,
  `src/ir/ast/declaration_plan.rs`, and
  `src/ir/ast/decbench_render.rs`.
- [x] Define authority order once in the program/session fact layer: analyst,
  trusted debug declaration, inferred recovery.
- [x] Preserve all candidates with provenance and record a typed
  `PrototypeConflict` health finding when they disagree.
- [x] Render the authoritative declaration's types, names, and variadic tail
  when representable.
- [x] Keep conflict diagnostics out of scored pseudocode by default. Expose
  them through structured Python results and an explicitly annotated analyst
  render mode.
- [x] Apply the same contract to all four entry points and propagated call
  sites.

### Tests

- [x] RED `tail_dispatch` exact prototype and parameter names.
- [x] Analyst-over-DWARF and DWARF-over-inference authority tests.
- [x] Stale/conflicting DWARF and PDB fixtures with both facts retained.
- [x] Variadic and aggregate declaration cases.
- [x] Scored-style determinism test proving metadata does not change text.
- [x] Stripped-lane recovery tests remain independent of declarations.

### Implementation evidence — 2026-09-02 DWARF/analyst increment

Implemented locally in `src/debug/dwarf.rs`,
`src/python_bindings/ir/dwarf_contracts.rs`,
`src/ir/ast/declaration_plan.rs`, `src/ir/ast/decbench_render.rs`, and
`src/ir/health.rs`:

- addressless C/C++ declaration DIEs are joined only through a unique defined
  text-symbol identity; non-C source declarations and ambiguous Rust/C++ local
  symbol names are not promoted into C declaration authority;
- source function and parameter names, types, and variadic state reach the
  signature and every corresponding body use through the declaration plan;
- analyst prototype tuples accept an additive fourth parameter-name list while
  retaining the shipped three-item form, and the CLI now transports names the
  project database already stored;
- analyst, DWARF, and machine-recovered candidates are retained as independently
  sourced `PrototypeConflict` entries in deterministic order, while scored text
  stays unchanged; and
- authoritative and inferred candidates fork from one recovery result, so
  provenance does not add a second whole-function type-recovery walk.

The first census attempt exposed `rustc:O0` `7898 -> 7924` undefined reads and
`rustc:O2` `5093 -> 5105`. The regression came from treating addressless Rust
DWARF declarations as C contracts. The language/identity guard above removed
the regression; the final unmodified baseline gate passed all six tests.

Validation at this increment:

- `cargo test --features python-ext`: 2,837 passed, 3 ignored, plus all
  integration targets and doc tests;
- `python/tests/test_decompiler_declaration_authority.py`: 4 passed;
- `python/tests/test_analyst_prototype_reaches_decompile.py`: 11 passed against
  a real compiled fixture;
- `python/tests/test_decompiler_defuse_census.py`: 6 passed, no baseline edit;
- native stub freshness and focused Ruff/ty checks passed. Whole-tree `ty`
  remains independently red with 335 pre-existing diagnostics.

### Implementation evidence — 2026-09-02 PDB declaration increment

Implemented locally in `src/symbols/pdb.rs`,
`src/python_bindings/ir/dwarf_contracts.rs`,
`src/ir/ast/dwarf_render_types.rs`, and `src/python_bindings/ir.rs`:

- module `S_GPROC32`/`S_LPROC32` procedure records now join exact code RVAs to
  `LF_PROCEDURE`/`LF_MFUNCTION` type records by TypeIndex; ID-stream records
  that cannot be resolved against TPI are rejected rather than guessed;
- PE image-base rebasing and CodeView build provenance travel with each joined
  declaration, and DWARF retains priority if a binary unusually supplies both
  trusted debug formats at one address;
- PDB scalar spellings distinguish CodeView `int`/`unsigned int`, `long`, and
  64-bit integer families, while tagged aggregate spelling is retained;
- complete PDB layouts referenced by declarations enter the existing debug
  type environment, allowing a real by-value `struct Point` parameter to be
  rendered and defined rather than flattened to `long`; requested layouts are
  collected in one bulk TPI scan rather than rescanning a large PDB per type;
  and
- all four decompile entry points consume the same map. PDB-versus-inference
  disagreements are reported as structured `PrototypeConflict` records with
  `authoritative_source = "pdb"`, outside scored text.

`python/tests/test_pdb_type_recovery.py` now has no prototype xfails. Its real
PE32+/PDB fixture proves five source signatures: by-value aggregate,
pointer-to-aggregate, mixed double/float, unsigned 64-bit return, and narrow
integer parameters. It also proves four-entry-point parity, metadata
provenance, and no-cache best-effort fallback. During conversion, the old
expected strings were corrected against `tests/pdb_types/types.c`: three
functions return `int`, not `unsigned int`, and `scale_pair` declares `char`,
not `signed char`.

Validation at this increment:

- `cargo test --features python-ext`: 2,839 passed, 3 ignored, plus all
  integration targets and doc tests;
- 12 focused Rust PDB tests, including real module-procedure joining and bulk
  layout lookup: passed;
- `python/tests/test_pdb_type_recovery.py`: 11 passed;
- declaration-authority and def-use census gates: 10 passed, with no baseline
  edit;
- native stub freshness and focused Ruff checks: passed.

### Implementation evidence — 2026-09-02 ABI and call-value increment

Implemented locally in `src/ir/value_number/parameter_slots.rs`,
`src/ir/call_contracts.rs`, `src/ir/call_result_split.rs`,
`src/ir/dead_stores.rs`, `src/ir/ast/dec_render.rs`,
`src/python_bindings/ir.rs`, and
`src/python_bindings/ir/callee_contracts.rs`:

- parameter-slot inference now follows reachable CFG paths instead of block
  address/storage order, so a scratch definition in one switch arm cannot hide
  a genuine live-in read in a sibling arm;
- exceptional-control-flow calls retain a result whenever their call contract
  proves one, while ordinary dead call results can still be discarded;
- two-register aggregate-return evidence survives call-contract refinement and
  result splitting instead of collapsing to a scalar carrier;
- non-C source declarations cross an explicit machine-ABI boundary: scalar and
  pointer aliases are normalized to representable C carriers, non-C aggregates
  do not silently impose the platform C aggregate ABI, and a hidden result is
  accepted only when the recovered void result, leading pointer, and exact
  one-parameter arity difference agree; and
- a call whose selected prototype returns `float` or `double` is rendered as a
  numeric value, not reinterpreted as integer bits through a union.

The parameter-slot algorithm is shared, but its register inventories remain
explicitly ABI-bounded: SysV AMD64, Win64, cdecl32 stack arguments, AAPCS32
soft/hard-float, and AAPCS64. This increment is therefore not evidence for
unsupported decompiler architectures or arbitrary language ABIs.

Validation used a freshly rebuilt release extension:

- focused Rust tests covered CFG sibling paths and every supported
  register-argument ABI;
- the full `168_rust_enum_niche` family had no scoped regressions, including
  the repaired `rustc:O2:rust_enum_discriminant` cell;
- `10_cpp_runtime_shapes`, `129_struct_by_value`, `168_rust_enum_niche`,
  `195_by_value_aggregates`, and `198_aggregate_return_edges` passed their
  18-lane full matrix without scoped regressions;
- `tools/dectest.py @calls @returns @structs` passed 36 of 838 selected lanes
  without scoped regressions after the float-call repair; and
- the four-lane default smoke selection passed without scoped regressions.

Known baseline failures in those families remain open; these commands prove
the bounded increment did not add regressions, not that aggregate, return, or
Rust recovery is complete.

### Implementation evidence — 2026-09-03 program-owned declaration authority

`src/program/environment.rs` now owns the single total declaration order:
inferred recovery, trusted PDB, trusted DWARF, then an explicit analyst
decision. Stable source labels come from the same type. PDB-versus-DWARF
selection, analyst-versus-debug selection, and conflict metadata in all four
binding entry paths consume that order instead of independently encoding it as
vacant-map insertion, `Option::or_else`, and raw strings.

The focused Rust authority test passes, and a fresh debug extension passes all
four real-binary declaration-authority tests, including deterministic scored
text and analyst-over-DWARF conflict provenance. At that snapshot the PDB suite
passed 10 of 11 because `record_value` still rendered `void *` instead of
`Record *`; the following increment closes that independently. The def-use
census fails closed on broad shared-tip drift in both directions; no baseline
was refreshed and no corpus movement is claimed for this output-neutral
change.

### Implementation evidence — 2026-09-03 nominal PDB aggregate pointers

The debug-declaration adapter now preserves authoritative `struct` and `union`
pointer spellings instead of passing them through the inferred library-catalog
normalizer, whose intentionally conservative fallback is `void *`. The real
PE32+/PDB fixture consequently emits `typedef struct Record Record;` and
`int record_value(Record *arg0)` rather than discarding the nominal type. The
generated translation unit passes strict C11 syntax checking.

The focused Rust regression test and all 11 tests in
`python/tests/test_pdb_type_recovery.py` pass against a freshly rebuilt debug
extension. Exact commands and output evidence are recorded in
`results/wp8-pdb-nominal-pointer.md`.

### Implementation evidence — 2026-09-04 Win64 home-slot dead store

The separately reported `record_value` body violation is now closed. The
clang-cl prologue `push rax; mov [rsp], rcx` reserves a word and immediately
homes the first Win64 parameter; stack promotion had rendered the unobserved
push value as `long local_8 = ret`, manufacturing an undefined source read.
Dead-store handling now removes only an adjacent, equal-width promoted-slot
write whose source is non-observable and whose replacement does not read the
slot. It declines partial writes, effectful expressions, self-dependence, and
control-flow crossings.

All 36 focused Rust dead-store tests and all 12 real PDB tests pass after a
fresh extension build. `record_value` has no `local_8`, produces no render-
verification finding, and compiles under strict C11. The smoke matrix reports
no scoped regressions. An exact clean-master A/B run proves the 12 failures in
the broader 85-test definedness/render/emission slice are unchanged current-
master defects. Commands and output are recorded in
`results/wp8-win64-home-dead-store.md`; no baseline was changed. The full Rust
gate is green. The def-use census remains red on its new-finding and
improvement ratchets because of broad current-tip drift in both directions;
the PDB fixture is outside that census and no corpus movement is attributed to
this increment.

### Implementation evidence — 2026-09-04 declared-call pointer boundaries

Call rendering now keeps parameter selection independent from result
representation conversion. A trusted declaration is no longer replaced with a
whole function-pointer cast merely because the recovered destination carrier
spells its return differently; incompatible parameter lists still retain the
per-site cast. At the argument boundary, the renderer now consumes the
declaration plan's selected local type, so a recovered `char *` local is passed
as a pointer rather than being weakened back to `(long)`. One pointer-width
transport cast may be removed only when the inner expression is already proven
compatible with the declared pointer parameter.

The real nullable-locale fixture improved from uncompilable calls such as
`strdup((long)old_locale)`, `strlen((long)saved_locale)`, and
`free((long)saved_locale)` to direct typed calls. All three libc pointer
fixtures compile, recompile, and execute equivalently. The full Rust gate and
the four-lane smoke matrix are green. The structural gate did not start a test:
its fixture setup lost the decompiler subprocess and waited indefinitely in
`subprocess.communicate`, so it was interrupted after 276.89 seconds. The
def-use census remains red on the same broad current-tip drift recorded above;
this fixture is outside that census and no baseline was refreshed. Exact
commands and limitations are in
`results/wp8-declared-call-pointer-boundaries.md`.

### Implementation evidence — 2026-09-04 pointer-return boundaries

Pointer-typed return and assignment boundaries now consume the declaration
plan's selected source type. When a pointer value retains one pointer-width
integer transport cast in the AST, the renderer removes only that redundant
machine representation: it emits a direct value for compatible pointer types
and preserves an explicit pointer-to-pointer cast for incompatible concrete
pointee types.

The real optimized linked-list fixture improves from
`return (node *)((long)var0);` (or the Clang `ret` equivalent) to a direct
pointer return. Both GCC and Clang variants compile and execute equivalently,
the adjacent libc pointer fixtures remain green, all 156 Rust pointer tests
pass, and the four-lane smoke matrix reports no scoped regression. The full
Rust gate is green. The required whole Python suite completed but remains
broadly red on 441 current-tip failures, dominated by the known-decompiler
recovery ratchet; no broad baseline was refreshed. Exact commands and limits
are recorded in `results/wp8-pointer-return-boundaries.md`.

### Implementation evidence — 2026-09-04 annotated declaration conflicts

The CLI now exposes the structured `PrototypeConflict` ledger through an
explicit `decompile --style decbench --annotate-conflicts` analyst mode. Each
requested annotation is deterministic, C-comment-safe, and placed immediately
before the affected signature with both prototype shapes, provenance labels,
and disagreement fields. Default and scored output remain unannotated.

Single, range, `--vas`, and whole-image routes are covered against the real
`tail_dispatch` fixture. Annotated single-function requests bypass the text
cache because drained provenance cannot be reconstructed from cached C. The
focused declaration, cache, generated-reference, and census suite passes all
36 tests; the existing DecBench-style CLI contracts pass all four selected
tests. Broader current-master failures remain visible and no baseline was
refreshed. Exact commands and limitations are recorded in
`results/wp8-annotated-conflicts.md`.

### Implementation evidence — 2026-09-04 DWARF variadic declarations

The DWARF reader now retains a direct `DW_TAG_unspecified_parameters` child as
an authoritative variadic fact and follows the same bounded, same-unit
abstract-origin/specification chain used for inherited attributes. The fact is
carried through the program-owned debug contract into `CallPrototype`, so GCC
and Clang declarations render `f(fixed, ...)` instead of the false fixed-arity
`f(fixed)` claim. PDB contracts remain explicitly non-variadic until their own
format adapter can prove otherwise.

The real four-lane variadic fixture proves all 12 combinations of GCC/Clang,
O0/O2, and three functions render the ellipsis. It also keeps the distinct
machine-to-C limitation visible: two GCC O2 bodies have no undefined reads,
while ten strict xfails still track incomplete SysV register-save-area and
`al` vector-count reconstruction. This increment therefore improves trusted
source declaration fidelity but does not claim generic stripped-binary
variadic inference or complete `va_start` lowering. Exact commands and results
are recorded in `results/wp8-dwarf-variadic-declarations.md`.

### Exit criteria

- [ ] No rendered prototype is worse than an available trusted declaration.
- [x] Conflicts are queryable with provenance.
- [x] Scored output contains no incidental diagnostic comments.

## 15. WP9 — Shared machine model and capability census

Purpose: make ISA/ABI facts explicit and turn missing-instruction discovery
into a standing test.

### Production changes

- [x] Inventory current ownership in `src/target/`, `src/ir/regview.rs`,
  lifters, ABI modules, stack recovery, naming, and dead-store handling. The
  result is `results/wp9-machine-model-inventory.md`.
- [~] Extend the existing `src/target/TargetSpec` boundary one fact class at a
  time. Do not introduce a competing `src/ir/machine/` identity: target ID,
  format/OS ABI, pointer width, instruction mode, PC rule, and special-register
  roles already live under `src/target/` with an exhaustive conformance table.
  Register views, ABI storage/effects, frame rules, and capability reporting
  remain split across IR consumers.
- [ ] Suggested target-owned query modules: `register_views.rs`, expanded
  `abi.rs`, and `capabilities.rs`; retain compatibility facades while callers
  migrate, and keep opcode semantics in the per-target lifters.
- [~] Add ARM32 register views, including VFP/NEON overlap, before migrating
  ARM32-specific shared-pass conditionals. `TargetSpec::register_view` now owns
  ARM32 core aliases and the complete `s0..s31`/`d0..d31`/`q0..q15` storage
  hierarchy. MIR register-effect completeness is the first consumer: `s0` and
  `d0` writes are opaque because each defines only part of `q0`, while a `q0`
  write is complete. Production SSA definition canonicalization is the second
  consumer: complete ARM core aliases use the target-owned parent, while
  partial `s`/`d` definitions deliberately retain their spelling until the
  lifter models their read-modify-write semantics. Remaining shared consumers
  and full VFP SSA identity are open.
- [ ] Migrate one fact class at a time: register overlap, clobbers/live-ins,
  argument/return locations, flag semantics, then silent writers.
- [ ] Keep lifter instruction semantics target-specific; share the queried
  contract, not necessarily implementations.
- [~] Add mnemonic capability census tooling and a documented exemption file.
  The standing effect census now has non-empty real-binary denominators for all
  four lifted targets, including i386, and validates every opaque mnemonic
  against `tests/decompiler_fixtures/effect_census_exemptions.json`. The gate
  rejects unreviewed names, count growth, overlapping matches, empty rationale
  fields, unknown targets, and exemptions which no longer fire. A second
  address-correlated census independently decodes each accepted LLIR block and
  requires every decoded instruction to produce a non-opaque LLIR op or match
  `tests/decompiler_fixtures/decoded_lift_exemptions.json`. Target, dynamic
  instruction-mode, compiler, and optimisation keys now have committed
  per-lane denominator and opaque-count ratchets.

The legacy packed binary32 arithmetic family is now explicit as well.
`ADDPS`, `SUBPS`, `MULPS`, and `DIVPS` lower to four existing typed scalar
intrinsics, with exact register/memory lane tests and no adjacent vector/HFA
regression. This improves fixture 217's Clang O2 output but does not close its
complex-helper call boundary. See `results/wp9-packed-float-arithmetic.md`.

### Tests

- [ ] Byte-identical fixture sweep for each architecture-only migration.
- [~] Extend architecture roundtrip and ARM32 semantic tests. The existing
  twelve-test ARM32 semantic module now pins the target-qualified definition
  identity through readable C and source-to-QEMU execution; broader
  architecture closure remains open.
- [x] New census test: every decoded mnemonic is lifted or has a reviewed,
  reasoned exemption. Both the post-lift opaque-effect census and the raw
  decoded-mnemonic-to-LLIR correlation are now enforced across all four lifted
  targets.
- [~] Ratchet `SILENT_REGISTER_WRITERS` toward zero. The standing x86 test now
  gives every remaining mnemonic an exact observed ceiling and rejects both
  count growth and stale entries. Sixteen-bit `bsr`/`bsf` now preserve their
  full register parents through explicit partial-read/write lowering, removing
  all four observed `bsr` occurrences. `cpuid`, `rdtsc`, `rdtscp`, and `xgetbv`
  now expose their complete architectural input/output dataflow on both i386
  and x86-64, removing 12 more observed silent writes; 19 reviewed mnemonic
  classes remained at that point. The exact 128-bit VEX `vpxor` register and
  memory forms now preserve both explicit sources, destination lanes, and the
  whole XMM view, removing four more silent writes; 18 reviewed mnemonic
  classes remained at that point. `pushfq` now exposes all seven represented
  flag inputs while retaining an honest unknown full flags word, and `popfq`
  extracts those seven bits from the loaded word while preserving both stack
  effects; four more observed silent writes are gone and 16 reviewed mnemonic
  classes remained at that point. The fixed-width YMM `vmovdqu` register and
  memory forms now transport all 256 bits as eight exact dword lanes, removing
  92 measured unmodelled forms and the `vmovdqu` silent-writer class. This does
  not claim general AVX semantics or first-class 256-bit LLIR storage. Fifteen
  reviewed mnemonic classes remained at that point. Exact eight-lane `vpand`
  now covers both register and memory sources, and exact `vpbroadcastb` reads a
  single byte and replicates it across all 32 destination bytes. Those remove
  four more measured forms and two more silent-writer classes. Thirteen
  reviewed mnemonic classes remain; the watched YMM form map is now only
  `vpcmpeqb` and `vpmovmskb`. The
  isolated `d14748cf` WP9 overlay passed the complete Rust gate with 3,080
  library tests passing, 3 ignored, and every integration and doc-test target
  green after `vmovdqu`; after the `vpand`/`vpbroadcastb` increment it passed
  again with 3,084 library tests passing, 3 ignored, and all integration and
  doc-test targets green.
- [x] Ensure `Op::Unknown` and generic intrinsic totals cannot silently grow.
  The per-target/mode/compiler/optimisation lane baseline requires zero
  `Op::Unknown` and caps the combined opaque plus modelled-intrinsic total for
  every measured lane. The combined WP9 overlay passed the complete isolated
  Rust gate: 3,071 library tests passed, 3 were intentionally ignored, and
  every integration and doc-test target passed.

### Implementation evidence - 2026-09-03 target-aware register reads

The production SSA path now distinguishes definition identity from read
identity. This fixes x86-64 partial reads such as `ax` observing the current
`rax` value, carries the exact SSA base through value numbering and MIR storage
inventory, and improves `cpp_template_int16:gcc:O2` from fail to pass without a
scoped x86-64 regression.

The required i386 sweep rejected an attempted standalone IA-32 register-view
model with 241 regressions across 410 lanes. That experiment was removed and an
explicit compatibility boundary retains historical i386 identity until the
lifter and all downstream consumers migrate together. The attempt, focused and
full-gate results, artifact hash, concurrent-worktree limitations, and remaining
three unaccepted i386 baseline regressions are recorded in
`results/wp9-target-aware-register-reads.md`.

This is one bounded WP9 increment. It does not close the shared target-model
ARM32/VFP, capability-census, or whole-architecture exit criteria below.

### Implementation evidence - 2026-09-03 ARM32 scalar VFP views

The first slice from `results/wp9-machine-model-inventory.md` is implemented in
`src/target/register_views.rs`, exposed through `TargetSpec`, and consumed by
MIR register-effect completeness. The target-qualified model keeps ARM core
and VFP banks distinct, maps `s0` and `s1` onto the low/high halves of `d0`,
and declines the same spelling under another architecture. Soft- and
hard-float targets share architectural storage while retaining distinct
calling conventions.

TDD and focused validation on the live shared snapshot:

- RED: target conformance did not compile because `register_view` did not
  exist; the MIR behavior test also described the former false-complete `s0`
  effect;
- `cargo test --features python-ext arm32_ --no-fail-fast`: 35 passed;
- `cargo test --features python-ext target:: --lib`: 5 passed;
- `cargo test --features python-ext ir::mir::tests:: --lib`: 15 passed; and
- release extension rebuild completed.

The slice was then overlaid by itself onto a fresh clone at `d14748cf`, with
the committed fixture build mounted read-only. In that isolated tree,
`cargo test --features python-ext` produced 3,065 passes, 0 failures, and 3
ignored tests. The same 410-lane ARMv7 O0/O2 sweep was run both on the isolated
slice and on an untouched control clone at `d14748cf`; both reported exactly
184 baseline regressions and 5 improvements. Thus the pre-existing ARM
baseline is red, but this slice changes zero lane verdicts relative to its
control. MIR remains an on-demand/debug analysis and the slice does not change
scored C.

The follow-up NEON increment makes `q0..q15` the widest canonical storage
parents: `s0..s3` partition `q0`, and `d0:d1` partition it. Its RED tests
proved that `q0` was absent and MIR falsely called a `d0` write complete;
GREEN validation passed all 35 ARM32-filtered tests, all 5 target tests, and
all 15 MIR tests. A fresh isolated overlay at `d14748cf` passed the complete
Rust gate, including 3,065 library tests with 0 failures and 3 ignored tests,
all integration binaries, and doc tests. Its release-built 410-lane ARMv7
O0/O2 sweep again reported exactly the untouched control's 184 regressions and
5 improvements, proving zero fixture-verdict changes from both the scalar and
NEON register-view increments.

Promotion is intentionally not claimed. A full isolated Python-suite attempt
was already producing failures in pre-existing fixture/decompiler groups and
was interrupted after roughly 22 percent when its process stopped yielding a
usable final report. Under the repository rule requiring the whole Python
suite after a source commit, that is not a passing gate.

The next increment migrated the duplicated ARM core-alias table out of
production SSA. `TargetSpec::complete_register_write_parent` is now the
fail-closed definition query: `a1` returns `r0`, a full `q0` write returns
`q0`, and partial `s0`/`d0` writes return no parent. Its RED conformance test
failed because the target query did not exist; GREEN validation passed all 5
target tests, all 12 SSA tests, and all 36 ARM32-filtered tests. An exact-file
isolated overlay passed the complete Rust gate, including 3,066 library tests
with 0 failures and 3 ignored tests, every integration binary, and doc tests.
The release 410-lane ARMv7 O0/O2 sweep remained identical to the untouched
control and both preceding slices: 184 historical regressions and 5
improvements, hence zero fixture-verdict changes attributable to the SSA
migration.

The attempted next step—unifying ARM scalar/vector SSA storage—was explicitly
deferred after inspecting the actual IR boundary. `Value::Const` is an `i64`,
while the widest `q` parent is 128 bits, and existing x86/AArch64 vector
lifters intentionally scalarise lanes rather than synthesize a 128-bit
read-modify-write. Canonicalising `s0` or `d0` directly to `q0` would therefore
manufacture a complete definition with no representable preservation of the
untouched bits. Full VFP SSA identity now has an explicit prerequisite:
scalarised ARM vector lanes or first-class 128-bit LLIR values and operations,
followed by real-instruction execution tests.

The independent capability-census increment added an existing committed i386
PE sample to the standing census corpus. A RED test first failed because the
per-architecture
census helper did not exist; GREEN now proves non-empty file, function, and
instruction denominators for i386, x86-64, ARMv7, and AArch64. The measured
report covers 10 binaries, 432 lifted functions, and 53,488 instructions,
including 26,089 i386 instructions that were previously invisible.

The follow-up RED test failed because no reviewed exemption manifest existed.
The new manifest records target, exact mnemonic or family, measured ceiling,
reason, semantic risk, owner, and removal condition. Its live gate covers all
236 current opaque effects: 194 i386 x87-family operations, 16 x86-64
`hlt`/`pause`/`ud2` operations, and 26 ARM `svc` or guarded-control effects;
AArch64 currently has zero opaque effects but retains a required denominator.
All 5 enforcing census tests pass, with the histogram reporter intentionally
ignored by the ordinary gate. An exact-file isolated overlay at `d14748cf`
passed `cargo test --features python-ext`: 3,068 library tests passed with 0
failures and 3 ignored tests, followed by every integration target and doc
test. This gate covers the combined ARM32 register-view, SSA-query, and census
increments without relying on the concurrently modified live worktree.

The next RED census used an empty raw-decoder exemption manifest. After the
audit was restricted to the exact function-owned block ranges accepted by the
lifter, it proved that no decoded instruction disappears entirely. It then
failed on the 236 decoded instructions which reach only maximally opaque LLIR:
194 i386 x87 instructions, 16 x86-64 trap/hint instructions, and 26 ARMv7
system-call or predicated instructions. The reviewed raw manifest records the
actual machine mnemonics independently of the normalized intrinsic names. Its
gate rejects unreviewed mnemonics, overlapping patterns, stale entries, count
growth, unknown targets, and empty review fields. The raw denominators are
6,236 i386, 8,394 x86-64, 812 AArch64, and 228 ARMv7 decoded instructions;
AArch64 has no opaque decoded instruction in this corpus. An exact-file
isolated overlay at `d14748cf` passed the complete Rust gate with 3,069 library
tests passed, 0 failed, and 3 ignored, followed by every integration target
and doc test.

Lane attribution is now enforced from committed provenance rather than filename
guessing. Each of the 10 corpus entries carries an explicit compiler and
optimisation identity sourced from its metadata sidecar and output path;
cross-built artifacts with no recorded optimisation level remain `unknown`,
and assembler output is `not-applicable`. A standing invariant rejects empty
fields, duplicate paths, missing binaries, or an unreviewed inventory-size
change. `effect_census_lane_baseline.json` splits the corpus into 10 actual
target/mode/compiler/optimisation lanes—including separate A32 and Thumb rows
from the mixed ARM binary—and requires each lane to retain its file, function,
and decoded-instruction denominator while its opaque count may decrease but
cannot grow silently. The exact-file isolated `d14748cf` overlay passed the
complete Rust gate with 3,074 library tests passed, 0 failed, and 3 ignored,
followed by every integration target and doc test.

### Implementation evidence - 2026-09-03 store-width demand

The bit-demand oracle now treats a register-valued memory-store source as the
width actually written, while retaining whole-value demand for address and
predicate operands. This removes the false entry-`rax`/undefined-`ret` input
from both Clang `atomic_flag_round_trip` lanes without inventing an initializer
or adding an architecture special case. The definedness module's six tests
pass, a narrow definition-health census reports no O0 or O2 violation, and all
four host atomic lanes remain baseline-stable. Exact RED/GREEN and fixture
evidence is in `results/wp9-store-width-demand.md`.

### Implementation evidence - 2026-09-03 interprocedural INTEGER pair

Direct-callee recovery now upgrades a call to the existing double-word INTEGER
carrier only when the callee must-define analysis proves both ABI result halves
on every reachable return and the exact caller consumes both before overwrite.
This removes the undefined `rdx`/`var4` from Rust trait-object `rust_dyn_apply`
at O2 and keeps O0 clean. Five positive/negative and cross-ABI proof tests and 18 adjacent
call-result tests pass; both Rust fixture lanes remain baseline-stable. The
broader host sweep measured 824/838 lanes but remains red from one infrastructure
crash and three scalar C++ regressions in the concurrent snapshot, none of which
crossed this new carrier path. Exact evidence and limits are in
`results/wp9-interprocedural-integer-pair.md`.

### Implementation evidence - 2026-09-03 Rust vtable tail calls

Prototype-backed tail-call recovery now joins the proven two-word callee result
with the exact terminal Rust vtable-slot load before converting an indirect
jump. O2 `rust_dyn_apply` consequently emits the real virtual call and return
instead of an unrecovered terminal jump, while four negative proof shapes stay
fail-closed. The complete Rust trait-object O0/O2 slice remains baseline-stable;
its remaining score failure is return-width/type cleanup, not missing control
flow. Exact proof conditions and gate limits are in
`results/wp9-rust-vtable-tail-call.md`.

### Implementation evidence - 2026-09-03 Rust scalar source types

The DWARF-to-C rendering boundary now translates Rust's fixed-width scalar
spellings into representation-preserving standalone C types. The real O0 and
O2 `rust_dyn_apply` fixture lanes consequently render their exported boundary
as `int rust_dyn_apply(unsigned int sel, int x)` instead of widening the return
to `long`; the clean O2 snapshot retains the previously recovered virtual call.
The conversion is deliberately outside the generic C catalog normalizer, so it
does not reinterpret Rust pointers or aggregates. Exact RED/GREEN and isolated
snapshot evidence is in `results/wp9-rust-scalar-source-types.md`.

### Implementation evidence - 2026-09-06 cdecl32 wide source parameters

Commit `fcd9bd2d` extends the bounded 32-bit wide-parameter carrier from
AAPCS32 register pairs to authoritatively declared i386 cdecl stack pairs. The
high incoming word is projected from the same source argument while the
promoted low `argN` role remains the whole value. Layout stops at unknown or
unsupported preceding parameter types. This moves nine fixture-202/215 O0/O2
cells to execution-correct output with no attributable regression across the
complete 410-lane i386 comparison.

An initially broader rewrite truncated the already-whole low role and caused
three scalar regressions. It was rejected before commit; those controls are
unchanged by the final implementation. Signed wide selectors and the i386 O2
mixed switch remain in WP6/WP7 and WP5 respectively. Exact contracts,
attribution, and gate evidence are in
`results/wp6-wp9-cdecl32-wide-parameters.md`.

### Exit criteria

- [ ] Shared passes no longer branch on architecture for migrated fact classes.
- [x] ARM32 has an explicit register-view model. `TargetSpec` owns its core
  aliases and complete VFP/NEON view hierarchy; SSA definitions and uses now
  consume the same target-qualified base. Migration of remaining consumers is
  tracked by the preceding exit criterion.
- [ ] The capability census is part of `default` or a clearly named required
  architecture profile.

## 16. WP10 — Verification, consolidation, and selective deletion

Purpose: finish the architectural migration, make release evidence fail
closed, and remove superseded code only after equivalence is demonstrated.

### Verification changes

- [x] Restore the independent LLIR invariants currently stranded in
  `src/ir/verify.rs` by compiling the module or porting each invariant to its
  correct owner.
- [x] Complete goto-aware used-before-definition using the WP1 winner.
- [ ] Promote `BlockDropped`, `EdgeUnaccounted`, `UsedBeforeDefinition`, and
  constant-false live latches to fixture/release failures.
- [ ] Preserve best-effort output with structured health/completeness metadata.
- [ ] Add lane-keyed O2 closure and effect expectations.

### Implementation evidence — 2026-09-02 LLIR verifier restoration

`src/ir/verify.rs` existed with production-grade checks for invalid width
changes, undefined temporaries, invalid memory access sizes, residual unknown
instructions, and explicit undefined values, but `src/ir/mod.rs` did not
compile the module. Restoring the module declaration turns those checks and
their real lifted-binary test back into maintained code.

Validation:

- before restoration,
  `cargo test --features python-ext ir::verify::tests -- --nocapture` selected
  zero verifier tests;
- `cargo check --features python-ext --lib` passed with the verifier compiled;
  and
- after restoration, the same focused test command ran all nine verifier
  tests, including `real_lifted_functions_have_no_fatal_errors`: 9 passed,
  0 failed.

This closes only the stranded-module item. The verifier is a query API, not yet
a release gate, and the remaining health promotion and lane-keyed expectations
below stay open.

### Implementation evidence - 2026-09-03 goto-aware definedness

`src/ir/verify_defs.rs` now builds a fixed-point CFG from the exact final AST
for functions containing labels and gotos. The graph includes nested
conditionals, loops, switches, breaks, exception arms, explicit labels, and
direct gotos. Missing or duplicate labels fail closed for the stronger
flow-sensitive claim; `NeverDefined` remains active, including for throw,
indirect-goto, and try/catch reads.

The focused suite passed 38 tests and the full
`cargo test --features python-ext` gate passed. A release-built, goto-heavy
fixture slice selected 20 of 838 lanes with no scoped behavior regressions.
The full def-use census correctly remained red: it surfaced newly visible real
undefined reads while concurrent work resolved many baseline findings, so this
increment did not rewrite the shared baseline. The structural test file also
remained red with the expected new exception-body finding plus unrelated
concurrent output/baseline drift. Commands, build fingerprint, scope, and the
detected repair targets are recorded in
`results/wp10-goto-aware-definedness.md`.

### Implementation evidence - 2026-09-04 performance-gate preflight

The post-`src/` full Python suite exposed a gate-ordering defect: the
incomparable-unit fail-closed test launched nine intentionally expensive
whole-binary decompilations before checking metadata that already proved the
run could not be compared. The same problem affected missing baselines and
impossible baseline references. The interrupted suite reached 71% in 1:51:36;
its 372 failures, 2,761 passes, and 892 expected failures are partial
accounting, not a completed gate result.

`ef24d729` moves those metadata-only exit-3 decisions ahead of measurement
while preserving real comparison, baseline-write, and runtime partial-result
paths. The four focused contract tests now complete in 0.62 seconds and assert
that rejected preflight states never enter measurement. Exact diagnosis,
commands, and limits are recorded in `results/wp10-perf-gate-preflight.md`.

### Selective deletion checklist

For each candidate module/pass:

- [ ] name the replacement owner;
- [ ] identify all production and test callers with `rg`;
- [ ] record firing/applicability evidence;
- [ ] remove one candidate per commit;
- [ ] run focused tests and `default` after each removal;
- [ ] run `release` after the deletion series;
- [ ] update the roadmap and this plan with the measured result.

Candidates include rejected MIR/MemorySSA code, old structurer compensation
passes subsumed by v2, `tag_phys`, `remap_type_map`, repeated orchestration,
and zero-fire loop-form passes whose applicability cannot be demonstrated.
The entire AST compensation layer is not a deletion unit.

## 17. Required validation by change class

### Documentation/tooling-only changes

```bash
uv run pytest python/tests/test_known_decompiler_failures.py -xvs
uv run pytest python/tests/test_defuse_ratchet.py -xvs
uv run pytest python/tests/test_decompiler_gate.py -xvs
uvx ruff check python/ tools/
uvx ty check python/
```

### Rust semantic changes

```bash
cargo test --features python-ext
uv run maturin develop
uv run pytest python/tests/test_decompiler_fixture_structural.py -xvs
uv run pytest python/tests/test_decompiler_defuse_census.py -xvs
```

### Pipeline/API changes

```bash
uv run pytest python/tests/test_decompiler_entrypoint_equivalence.py -xvs
uv run pytest python/tests/test_decompiler_determinism.py -xvs
uv run pytest python/tests/test_decompiler_session.py -xvs
```

### Full completion gate

```bash
scripts/decompiler-gate.sh release
```

Until that script exists, use the commands in `CLAUDE.md` and record exactly
which lanes ran. Never describe an unrun or partial lane as green.

## 18. Measurement report required for every output-changing increment

Store a Markdown report under:

- `docs/history/decompiler-review-2026-09-02/results/<work-package>-<slug>.md`

Each report must include:

- before and after Git revisions;
- exact command lines and build fingerprint;
- focused test RED/GREEN evidence;
- fixture cells improved, regressed, and unchanged;
- C and Rust counts separately;
- structural goto/switch/break changes;
- execution-differential result;
- GED, type, byte, and Union changes when evaluated;
- wall time and RSS;
- accepted trade-offs or reason for revert.

Do not refresh a baseline merely to make a regression green. Any accepted
regression needs a written semantic justification and an explicit entry in the
relevant ratchet's accepted-regression record.

## 19. Milestones

### M0 — Evidence is trustworthy

- [x] WP0 complete at `7aec4e842fa1`; the generated inventories and gate
  contracts were established in `eb6484ce` and the core-facet preflight was
  corrected in `7aec4e84`.
- [x] Existing committed baselines are cited at pinned revision
  `e55576bc4612` in the active-roadmap status entry.
- [x] Gate profiles identify their denominator and fail closed.

### M1 — Capability work is producing evidence

- [x] WP4 is running in shadow mode on the first three RED fixtures, with v1
  still the sole production authority.
- [x] WP5 has a host jump-table vertical slice: the real gcc-O2 Duff dispatch
  resolves eight ordered targets in discovery and carries values `0..7` plus
  its typed bypass edge through the independently verified WP4 tree and into
  deterministic parseable switch output. The v1 production path remains
  unchanged until WP4 promotion evidence is complete.
- [x] WP7A landed at `81ffe9ab` with width-aware equivalence, real-binary
  readability, execution, and def-use evidence.

### M2 — Dormant architecture decision made

- [x] WP1 experiment complete: the production definedness consumer was
  rejected on its hard performance criterion and removed; see
  `mir-trial-results.md`.
- [~] MIR is not a named production authority. Its production consumer was
  removed, while responsibility-by-responsibility substrate deletion remains
  a WP10 item because independent verifier/object/type tests are retained.

### M3 — One semantic pipeline

- [~] WP2 is complete; WP3 remains open.
- [x] Entry points agree at equal budget.
- [~] Semantic consumers use stable values, not display names. Exact float-role
  projection and optimized DWARF register-local recovery are the first two
  migrated AST-side product consumers; the remaining name parsers keep this
  criterion open.
- [ ] Origin mappings are deterministic.

### M4 — Largest measured defect classes closed

- [ ] WP4 and WP5 complete.
- [ ] Whole-function structural fallback is no longer the default failure
  mode.
- [ ] Switch target evidence reaches structuring.

### M5 — Types and readability improve safely

- [ ] WP6, WP7A, WP7B, and WP8 complete.
- [ ] C type/return axes improve.
- [ ] Every idiom has width-aware equivalence evidence.
- [ ] Trusted declarations render authoritatively with out-of-band conflicts.

### M6 — Architecture and release closure

- [ ] WP9 and WP10 complete.
- [ ] Release profile is green at a pinned commit.
- [ ] Final local DecBench evidence is complete and internally archived.

## 20. Immediate next actions

1. [x] Recover nested post-tested rendering without flattening conditional
   arms. Commit `80f5d106` preserves ordinary internal conditionals and absorbs
   only the exact typed latch. A missing lexical continuation is materialized
   only when its LLIR block is an unconditional-return tail. The release-built
   pinned corpus reports zero regressions across 334 executable candidates;
   see `results/wp4-nested-post-tested-rendering.md`.
2. [x] Replace the preserved nested loop-header gotos with a proved
   source-level `continue` representation. Commit `85a61693` introduces an AST
   `Continue` only while lowering transfers to the current multi-exit loop
   header; traversal does not cross nested loops. The pinned 715-function
   comparison reduces comparable shadow gotos from 584 to 324, moves improved
   rows from 204 to 220, and reduces nine unexplained regressions to zero. The
   250-candidate execution comparison remains at zero regressions. See
   `results/wp4-source-level-continue.md`.
3. [x] Complete the required O0 `classify` WP6/WP7 vertical slice above.
   Commit `9c9c607c` adds real GCC/Clang debug and stripped fixtures and lands
   the width- and signedness-proved `> 100` predicate fusion with proof,
   refusal, syntax, differential, and scoped-corpus evidence. Commit `5fdd0c8f`
   adds stripped signed-return evidence and redundant-cast cleanup at the SSA
   result-fact and typed-AST boundaries, with a genuinely unsigned control.
   The clean exact-checkout Rust gate is green, and both `classify` tests pass
   within the whole Python run. That whole run remains broadly red (121
   failures at the prior slice, 115 at `2be036eb` before its mechanical census
   refresh), which is recorded rather than promoted to a release claim; see
   `results/wp6-classify-signed-return.md`.
   Report O2 separately rather than claiming source-loop recovery after
   strength reduction or unrolling.
4. Finish the other WP4 promotion evidence. The remaining Duff and clang-wide
   rows are classified at `ca91dc68` by exact, fail-closed
   suffix/shared-effect-entry contracts, and the clean pinned full comparison
   reports zero unexplained regressions without rewriting the four raw
   regression statuses. The corpus-wide execution route is now live; still
   complete unexplained block/edge accounting, pinned GED, structure-axis
   movement, and accepted runtime/output-size budgets.
5. Extend the landed WP5 shared typed-case transport across the remaining
   fixture/compiler/architecture execution cells and classify every residual
   decline. At `9ad9414d`, `Cfg` is the single producer of immutable ordered
   case/default/provenance evidence consumed by production and v2; incomplete
   or inconsistent evidence declines before recovery, and the verifier checks
   the relationships independently. Malformed, truncated, overlapping, and
   wrapping table safety tests and the new chained inclusive/exclusive guard tests are
   already present and must remain green. Fixture 204's Clang O2 seven-case
   evidence now reaches the production structurer, passes all 34 execution
   cases, and has moved its baseline from `fail` to `pass`; the remaining work
   now has clean accounting through explicit borrowed return-tail provenance.
   The unverified compiler/architecture cells, remaining matrix gates, and
   residual decline census remain. The AArch64 slice's full Python gate has run
   and is triaged but remains broadly red; do not call WP5 complete from the
   green Rust gate or focused retry evidence alone.
   The next i386 slice at `b84233ec` removes eight more O2 failures with zero
   attributable regression across all 410 i386 lanes. Its full Rust and focused
   execution gates are green; its whole Python suite is complete and has zero
   tip-only failure IDs, while remaining broadly red at 125 failures.
   The stacked ARMv7 A32 slice at `76cce5d1`/`5ef0bcb9` removes nine more O2
   failures with zero attributable decline across 1,604 function verdicts.
   Commit `6f0ba701` then closes the isolated production-v1 loop-backedge
   ownership failure; its exact full A32 comparison adds the intended
   `dispatch_in_loop` fail-to-pass movement with no attributable decline.
   Commits `28b3bc5b` and `0e29ffc4` remove the surviving outer-guard goto and
   undefined-looking temporary as separately proved quality work, with no
   attributable decline in the exact host/A32 comparisons. Commit `c9483542`
   then replaces the raw loop's six exact header-backedge gotos with
   source-level `continue`, with no attributable A32 status change. Next
   `460259fa` carries the shared typed case/default evidence into that raw loop;
   the real guard-only default is no longer lost merely because it is not a
   dispatch successor. `88e6584c` folds the now-redundant proven range guard
   into that switch, removing its temporary, conditional, and goto without
   changing execution. Continue with Thumb loop tables, AArch64 adjacent-table
   variants, and wide-selector forms. For handler inlining, add a verified
   presentation partition over the canonical raw ownership: exclusive arm
   prefixes, optional guard-only default prefix, one unique shared join, and
   residual blocks. Refuse external handler predecessors, cross-arm edges,
   cycles, non-unique joins, or any partition that would emit a block twice.
   `13588284` completes the first one-block exclusive-entry slice and removes
   every goto from the real A32 function. Extend it through multi-block private
   prefixes only after proving interior predecessor closure and an exact stop
   at the unique shared join; retain the current refusal rules otherwise.
   `ca30c62f` completes that bounded straight-line extension with an independent
   verifier: interiors are exact one-predecessor/one-successor chains, prefixes
   are disjoint and capped at eight blocks, and a forged shared-join crossing
   is rejected. Its exact-tip structural run has no attributable regression or
   improvement: exact parent/tip rendering is byte-identical for every row in
   both red aggregate ratchets, which are retained for explicit baseline
   review. The full def-use census is also parent/tip identical: four of six
   tests pass and the two aggregate baseline-drift ratchets remain red.
   Commit `1ce1a80b` completes the next bounded branching slice: a typed arm
   may own a deterministic, predecessor-closed private DAG of at most 16
   blocks. Its independent verifier accepts a private diamond and rejects a
   forged region crossing a case/default shared join. On a real GCC ARMv7 A32
   byte-table loop, case 0 moves from two out-of-line gotos to an inline
   `if (acc <= 6)` with native execution preserved. Cyclic regions, cross-arm
   ownership, shared-join ownership, and general unique-join partitioning
   remain refused; do not widen them without equivalent independent proof.
   Its exact structural and def-use reports reproduce every preceding
   regression/improvement finding without adding a row: 25 of 27 structural
   tests and four of six def-use tests pass, with both two-sided baseline-debt
   ratchets intentionally still red. Its required release-built whole-Python
   parent/tip replay also finds zero tip-only failure IDs: parent `33aed1ae`
   has 116 failures and tip `146bd4c8` has 115, with the sole removed failure
   being the intentionally refreshed test census. Both runs have 4,621 passes
   and 889 expected failures. Parent has 69 skips versus tip's 71 because two
   stripped fixture-08 objects were absent from the tip run's externally
   selected fixture directory; this is recorded as an environment mismatch,
   not an implementation result. The suite therefore remains broadly red and
   the timing is not a matched performance comparison.
   See `results/wp4-raw-switch-private-branches.md`.
   The following host wide-selector slice at `9333881e` recovers Clang and GCC
   O2 fixture-215 `wide_selector_mixed`, including the case-zero return shared
   with the formal default. Its first full def-use census exposed one real
   fixture-206 loop-switch regression from over-broad predicate/cyclic
   ownership. Hardening commit `98a0d2d3` rejects arithmetic ancestry, limits
   transitive provenance to boolean operations, and refuses transitive dense-
   guard folding inside cyclic ownership. Fixture 215 and both the host-Clang
   and ARMv7 fixture-206 controls now pass together; the normalized def-use
   report is again exactly the preceding 169 findings. Continue the wide-
   selector matrix only from this hardened boundary. Its exact whole-Python
   comparison attributes all nine new failure IDs to strict-XPASS
   improvements, with no ordinary regression, and `0466a2e0` refreshes the
   full 1,676-object defect inventory (38 to 30 unrecovered observations;
   6,823 to 6,502 gotos). See
   `results/wp5-wide-selector-shared-return.md`.
6. [~] Continue WP3 as the active architecture lane now that WP2 is complete.
   Commits `925dc002` and `09522773` establish conservative versioned SSA
   invalidation across definedness and return materialization. Commit
   `f05c9a5d` carries exact-or-ambiguous opaque identities through AST lowering
   and migrates float-role projection as the first consumer. Commit `af65c260`
   migrates the DWARF register-local resolver as the second consumer. Both are
   byte-identical across the 419-pair gate. Commit `7bea3314` introduces the
   deterministic compositional origin-set primitive and remains byte-identical
   across the same map. Commit `59840017` attaches it transparently to
   statements, converts the 64 exhaustive consumers, and proves rendering and
   the complete 419-pair map remain byte-identical. Next finish the wildcard
   consumer audit, union origins in folds, preserve them through remaining
   structuring/duplication paths, and expose structured Python line mappings
   before continuing consumer migrations. Commit `8cb7d171` already attaches
   each `LlirInstr.va` during lowering; `cda7ab73` closes the exception-recovery
   consumer and moves the stripped differential from 103 to 102 regressions.
   Commit `cb9e5b10` closes six more control-oriented wildcard consumers with
   an exactly neutral 102-regression/17-improvement stripped differential; next
   `52914784` migrates `guarded_switch`, and `f7b47953` migrates the complete
   `guard_chain` consumer with an exactly neutral differential. Next migrate
   `switch_ladder`, then `latch_predicate`. Commit `3b7d8a95` completes the
   `switch_ladder` migration with another exactly neutral differential; next
   migrate `latch_predicate` and re-audit the wildcard surface. Commit
   `a807b2d0` completes that migration with another exactly neutral
   differential. The re-audit identifies the enabled
   `aapcs64_indirect_result` pre/post-stack-promotion consumer as the next
   bounded omission; commit `c51a116d` completes that migration with neutral
   stripped and whole-Python comparisons. Next migrate the enabled
   `vector_copy` consumer, including exact unions for removed lane batches and
   scalar-view bridges, before expression ownership. Commit `02b0da5c`
   completes that migration with eight focused tests, a neutral stripped
   differential, an identical normalized 221-node whole-Python failure set,
   and an eight-for-eight green undeclared-local invariant. Next migrate the
   remaining raw guarded-return and diamond paths in `select_fold`. Commit
   `e92d7248` completes that migration and removes three whole-Python failures
   with zero additions; re-audit the remaining enabled wildcard surface, then
   start expression ownership and the non-contiguous transformation policy.
   Commit `18ef9fdc` migrates GOT folding, `217796be` migrates relocation-proven
   function tables, and `849c5a5b` migrates direct, resolved-indirect, and
   vtable tail calls. The last increment is stripped-neutral and removes the
   Rust O2 trait-object unrecovered-tail failure with zero additions. Next
   migrate the convention-generic recovered-layout folds in `call_args.rs`,
   followed by the bounded cdecl32 and AAPCS setup/removal paths.
   Those three call-argument surfaces are complete at `a0917da5`, `c291328a`,
   and `e403de27`. The subsequent audit selected the stack-canary consumer;
   `9942f948` completes it with 22 focused tests, an unchanged
   102-regression/18-improvement stripped differential, and an exact-neutral
   211-node whole-Python comparison. Integer-pair return composition follows at
   `8989cecc`; the normalized semantic failure set and stripped differential
   remain neutral. Commit `82a95253` then closes six related raw call-analysis
   readers as one batch, with six observed-red tests, 109/109 call-argument
   tests, 54/54 origin-focused tests, and a green complete Rust gate. Its exact
   whole-Python failure set improves from 211 to 209 with no additions, and
   focused release A/B proves both indirect-tail/table-dispatch removals are
   attributable. Commit `b84c03e5` then migrates
   `src/ir/lazy_call_select.rs` in both AST preparation and the DecBench
   renderer path: recognition, recursion, goto census, consumed-origin unions,
   and replacement ownership move together. Five focused tests were observed
   red; 18 module and 58 origin tests pass, along with the release
   compiled/stripped check, all 20 fixture-189 functions, and the complete Rust
   gate. Its whole-Python gate has zero attributable failure-set change after a
   release parent/tip classification. Re-audit the remaining enabled semantic
   consumers before starting expression ownership.
   Commits `7d531781` and `4b35aeab` next close four final-cleanup readers plus
   the dead-store surface. Seven focused cases were observed red; all touched
   modules are green, and fixture 11 remains 52/52 while losing fake result
   temporaries on effect-only calls. Finish the remaining wildcard audit, then
   define non-contiguous transformation behavior and start expression
   ownership. See `results/wp3-final-cleanup-origins.md`.
   Commit `025937a7` closes seven more output-value readers and in-place
   rewrites across four modules. The origin filter is 62/62, fixture 11 is
   52/52, and the focused AArch64 result-lifetime plus ARM frame-spill checks
   pass on a release build. Complete the wildcard classification, define the
   non-contiguous transformation policy, and only then migrate the
   store/return-synthesizing bank composition paths. See
   `results/wp3-output-value-origins.md`.
   Commit `6068a59c` now migrates that first complex path under the explicit
   policy, and `876bddf6` closes the adjacent raw loop-exit and boxed-call
   omissions in `call_result_split.rs`. Commit `c6a42332` next closes the
   final-source verifier and authoritative pointer reader surfaces. Continue
   with canonical local naming and architecture-specific prologue readers;
   keep expression ownership behind completion of that audit.
   Batch related migrations and use focused fixtures during
   development, paying whole-repository gates once per coherent source batch.
   Keep `Invalidate::All` as the legacy default while passes migrate.
7. Continue WP6 from the landed stripped-C per-use signedness, SysV hidden
   result-buffer, split INTEGER+SSE, and homogeneous SSE-pair return slices.
   Fixture `197` is now closed across its four host lanes: all non-structural
   helpers and wrappers pass, with nine former O2 failures removed and no
   adjacent aggregate regression in fixtures `195` or `198`. Next, add the
   general equality, pointer, pointee, aggregate, call, confidence, and stable-
   value constraints rather than extending fixture-specific ABI adapters.
   Keep Rust totals separate and do not generalize the SysV/x86 evidence to
   unsupported architectures, vector forms, or language ABIs.
   The fixture-215 signed-edge slice at `8ab39b50` is the model for boundary
   conflicts: retain the authoritative declaration, attach the machine
   interpretation to one use, and refuse inferred declarations. Extend that
   model through stable WP3 identities rather than adding renderer name rules.
   The first fixture-217 prerequisite models legacy packed binary32 arithmetic,
   and the following bounded compiler-runtime boundary is landed. Direct SysV
   calls to `__mulsc3`/`__muldc3` now carry exact source-ordered
   `xmm0`..`xmm3` layouts. The result model distinguishes the packed two-float
   `xmm0` carrier used by `__mulsc3` from the two-register `xmm0:xmm1` result
   used by `__muldc3`; it does not incorrectly describe both helpers as
   multi-register returns. The four GCC/Clang O2 complex-multiply cells pass,
   with scalar, integer-pair, HFA, vector-transport, and incomplete-layout
   controls retained. Next, generalize the exact boundary fact beyond the two
   catalogued compiler helpers and complete exceptional-input execution
   evidence without weakening the fail-closed layout rules. See
   `results/wp6-compiler-complex-helper-boundary.md`.
8. Close WP8's remaining corpus-wide exit evidence. Declaration authority,
   structured conflicts, and the explicitly requested analyst annotation mode
   are landed; scored text remains free of diagnostics by default.
9. Continue WP9 from the landed ARM32 register-view and capability-census
   slices: migrate one remaining shared consumer or fact class at a time,
   reduce the 13 reviewed silent-writer mnemonic classes, and wire the census
   into a named required architecture profile. Do not canonicalize partial
   VFP/NEON writes until LLIR can represent the untouched lanes.
   The AAPCS32 wide-parameter slice at `62a4ab72` additionally carries both
   little-endian core-register words of an authoritative eight-byte integer
   parameter into one source argument. Continue with the residual A32 O0
   frame/storage identity failures and an independently specified i386 pair;
   do not generalize this declared-parameter fact to inferred values before
   WP3 provides stable identity. See
   `results/wp6-wp9-aapcs32-wide-parameters.md`.
   A first spelling-level `fp`/`r11` frame-alias prototype fixed the two A32 O0
   fixture-215 cells but caused 188 regressions in the complete 410-lane A32
   O0/O2 comparison and was rejected. Resume only with exact SSA-definition
   lifetime evidence; never make the architectural alias globally active.
10. Under WP10, triage the current red full-gate failures by exact base/overlay
   comparison, promote only independently justified health findings to release
   failures, and remove rejected MIR or compensation code one owned
   responsibility per commit. The metadata-only performance-gate hang is
   closed at `ef24d729`; the remaining full-suite failures and unbounded real
   measurement paths still require triage.
