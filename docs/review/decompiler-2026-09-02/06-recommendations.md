# 06. Ten recommendations

Ordered by leverage. Each names the evidence it rests on (by section of this
review), what to build, what the docs already said about it, and how it would
be judged. The roadmap's rule applies throughout: correctness work is judged
by cells moving; architecture work is judged by a boundary that holds and is
expected to move zero cells.

Recommendations 1, 2 and 4 attack the two largest measured failure classes
directly. 3 and 10 are what make 1 and 2 safe to do. 5 through 9 are
independent of each other and of the first four.

## 1. Replace the structurer with a total, locally-degrading one, then retire redundant compensation

**Evidence.** 715 functions and 6,791 gotos in goto-free source (04 section
1.2), evenly spread across compilers and optimisation levels. The region
algebra has one `exit` per loop and one `join` per conditional, no `Return`,
no `Continue`, and no short-circuit shape (01 section 3). Three pre-build
shape predicates plus post-build accounting can cost a whole function its
structure. Five of the six hand-decompiled functions in 03 show control-flow
or dispatch shapes the current pipeline cannot represent. The 2026-08-27
reproduction concluded "any redesign must grow the region algebra first;
patching the predicate is what was tried twice and reverted twice", and the
structuring design doc prescribed a total structurer behind a flag with shadow
mode that never started (05 sections 2 and 3); the sixth hand-decompiled
example is primarily a prototype/type case.

**Build.** A dominator-tree region structurer that:

- represents multi-exit loops with `break`, `continue` and `return` as
  first-class region nodes, so a loop with an early return and a normal exit
  (03 section 3.2) is a `while` with a `return` inside it;
- recovers conditions by reaching-condition reasoning (the DREAM approach) so
  a condition DAG (03 section 3.1) becomes `(a > 0 && b > 0) || c > 0`;
- degrades locally: an unrepresentable sub-graph becomes a labelled region
  inside an otherwise structured function, never the whole function;
- duplicates small terminal blocks (tail duplication of a return block) and
  flattens `else` after `return`, which are the two cleanups 03 section 3.3
  needs;
- consumes recommendation 4's authoritative typed case edges rather than
  re-recognising ladders.

Ship it behind a flag in shadow mode, exactly as `semantics-preserving-
structuring.md` section 6 prescribed. Judge it on three things together: the
715-row axis, the execution differential, and GED on the DecBench sample. The
goto-sinking experiment (05 section 3) is the caution: fewer gotos with a
CFG further from the source loses. The target is the source's structure, not a
goto count.

**What the 715 rows do and do not prove.** "The source has no goto" is a
pressure metric, not a theorem that every optimised CFG structures without
one. Tail merging, cross-jumping and jump threading can produce a graph that
is irreducible or that shares a block between contexts the source never
shared, and an honest `goto` there is the correct output. The axis therefore
needs a third state beside pass and xfail: an accepted honest goto, recorded
per row with the CFG property that forces it (irreducible loop, shared
multi-context tail, dispatch loop) and counted separately. The judge for
recommendation 1 is the goto count trending down while the differential and
GED hold, with the accepted-honest set growing only by triaged rows.

**Then retire selectively.** Once the new structurer wins, delete only
compensation passes whose behavior is subsumed and whose removal is proved
neutral by the fixture matrix. Some modules in the 11,303-line layer also
perform useful canonicalisation beyond compensating for the old structurer,
so the whole set is not automatically dead. Classify the two zero-fire passes
against intended rare/target-specific coverage before retiring them.

## 2. Run dataflow on SSA and carry value identity and instruction origin into the AST

**Evidence.** Copy propagation, constant folding, dead-store elimination, DCE,
stack promotion and argument recovery all take `&mut ast::Function`, a flat
`Vec<Stmt>` with no value identity (01 section 2). `compute_ssa` runs up to
four times per function and one `value_number` result is discarded (02).
Value numbering mangles `reg#version` into physical-register strings that
consumers parse back. `remap_type_map` reconciles two type maps by role name.
Presentation names (`ret`, `arg0`, `local_`) carry semantics in 12 product
files (01 section 8). `typed-ssa-hlir.md` Phases 3-4 and `value-model-root-
cause-and-plan.md` Phase 2 planned this and stopped (05 section 2).

**Build.** One authoritative SSA state, not literally one construction: a
versioned `SsaInfo` owned by the pipeline object with explicit invalidation,
so a transform that changes the CFG or the definition set declares it and the
state is repaired (incrementally where possible, by reconstruction where not)
before the next consumer reads it. What is not legitimate is today's shape,
where four full constructions happen because no stage can say what changed.
Copy propagation, constant folding, DSE and DCE as SSA passes on the LLIR,
before lowering. `ast::lower` then lowers a
clean SSA into an AST whose `Expr` carries `SsaValue` and whose `Stmt` carries
a compositional origin set (one or more instruction addresses). A single
address is insufficient after folding, hoisting, or joining expressions.
Delete `tag_phys`, the `#`-parsing consumers,
and `remap_type_map`. Naming becomes a render-time map from value to display
name, not a rewrite of the program.

**Why origin belongs here.** `Stmt::Origin` is the number-one gap in the UX
ranking and the reason the DecBench line-mapping issue draft (`DECBENCH-ISSUE-
DRAFT.md`) says "we cannot provide reliable `line_mappings` yet". It costs
nothing extra if identity is being threaded through anyway.

**Judge.** Architecture track: byte-identical output over the fixture corpus
(the 419-binary byte-identity sweep exists), then a shorter pipeline, then the
line map.

## 3. Time-box one MIR production consumer, then keep or delete on evidence

**Evidence.** About 8,700 lines (`mir/`, `memory_ssa.rs`, the memory-object
substrate, `DefinitionOracle`) with no semantic production consumer; the only
hook is `#[allow(dead_code)]` and the only other production-path construction
is the debug dump (01 section 6). The first attempted
consumer (frame-extent join) reproduced what `stack_locals` already computed
at +10.4% cost and was judged "not a migration" (05 section 3). The alias
barrier needed no MIR because 72% of its cases were provable from the AST
(roadmap). `src/ir/verify.rs` has been uncompiled since 2026-08-12;
`effect_census.rs` has no non-test caller.

**Recommendation.** Keep MIR for one explicitly time-boxed increment and wire
one bounded production consumer that needs its definition or memory identity.
Measure cost and unique decisions. If no such consumer demonstrates value,
delete MIR/MemorySSA rather than maintain a parallel authority. Restore the
LLIR invariants from orphaned `verify.rs` independently.

**The named trial.** The consumer is the path-sensitive
`UsedBeforeDefinition` check that `verify_defs.rs:30-40` skips on every
goto-bearing body. `DefinitionOracle::all_paths_defined` is exactly that
question asked over a CFG rather than a structured tree, it already exists
with tests (`mir/mod.rs:294, 335`), and it is read-only, so the trial cannot
change output. The unique value it must show: definedness verdicts on the 715
goto-bearing functions (473 after deduplication) that the AST walk cannot
reach, expressed as new rows in the def-use census.

| term | value |
|---|---|
| budget | one increment: two working days, one commit series, no new fixture builds |
| required unique value | at least one `UsedBeforeDefinition` finding on a goto-bearing function that the structured walk cannot see, or a proof that the 715 are clean; either is evidence the AST could not produce |
| cost ceiling | under 10% added wall time on the fixture matrix (the frame-extent attempt was +10.4% for nothing) |
| deletion threshold | any of: no finding and no proof within budget; cost over the ceiling; or the verdicts reproducible from an SSA-level walk on the LLIR (recommendation 2) at lower cost |

If the trial fails, delete `mir/`, `memory_ssa.rs` and the MIR adapter in
`memory_objects/` in the same series that records the measurement. Two
earlier candidates (the frame-extent join and the alias barrier) already
returned nothing and should not be re-run.

Track pass firing as evidence, not an automatic failure: a sound rare-target
pass may legitimately fire zero times in the host corpus, and a successful
upstream rewrite can make a downstream pass obsolete. Zero-fire passes require
an applicability fixture or an explicit retirement decision; they should not
make every structural run red merely for being dormant.

## 4. Add jump-table analysis whose typed case edges reach the structurer

**Evidence.** All 48 `unrecovered` rows are switch dispatch (04 section 1.4);
`102`, `103`, `145`, `154`, `215`, `206` supply 8 wholly-failing host lanes.
`indirect_targets.rs` (432 lines) resolves PLT and GOT slots and leaves table
dispatch alone. Duff's device is unresolved at clang -O0 with an explicit range
check and at gcc -O2 where the index is `arg2 & 7` with no compare at all,
even though the readonly-data folder had already enumerated all eight table
entries inline (03 sections 3.4 and 3.5). 85 switches are recovered
corpus-wide against 4,604 gotos.

**Build.** A bounded value-set analysis on the jump index that understands a
compare-and-branch guard, a mask (`& 7`), a subtract-and-unsigned-compare
range check, PIC-relative offset tables (`table[i] + table_base`), absolute
tables, ARM `tbb` / `tbh`, and `ldr pc, [pc, r0, lsl #2]`. Carry the resolved
cases as typed CFG evidence attached to the existing `IndirectJump`, with one
authoritative target set consumed by discovery, accounting, structuring, and
rendering. Add `Op::Switch` only if it replaces rather than duplicates CFG
target ownership and its execution semantics are defined. The requirement is
that the structurer sees typed case edges with values and never re-recognises a
comparison ladder at AST level.

**Also.** Add a strict xfail today for the `if (0) { goto L_1180; }` latch in
`102_duffs_device-gcc-O2.so::duff_copy` (03 section 3.5). It is a wrong
answer hidden behind an `unrecovered` marker.

**Judge.** The `unrecovered` axis to zero; the eight lanes; the `switch` count
in the readability census.

## 5. Build the constraint-based type recovery the docs proposed twice; decide whether Rust ABI is in scope

**Evidence.** `TypeHint` has no struct, array or typedef; the join is
flow-insensitive and unsigned is sticky (01 section 4). `tail_dispatch` types
`tag` as `unsigned int` because the compiler implemented `tag < 0 || tag >= 5`
as an unsigned compare (03 section 3.6). Signedness is 187 of the 307
parameter rows. Retypd / TIE-lite typing was project #3 in
`decompiler-refactors.md` and parity #6, and the roadmap says "no constraint
type, no solver" (05 section 2). 298 of the 307 rows and 59 of the 92 return
rows are Rust fixtures (04 section 7).

**Build.** Keep the three-layer model from `semantics-preserving-
structuring.md` section 3.3: machine width as truth, signedness as a per-use
interpretation, recovered type as a hypothesis with confidence. Collect
constraints from uses (loads, stores, comparisons, call sites, ABI) and solve
them; render a low-confidence signedness as the machine width with an honest
cast, not as an assertion. An unsigned range-check idiom contributes a range
constraint, not a signedness. Add pointee and aggregate constraints so
`char **` (parity #6) and by-value structs (the PDB xfails) have a home.

**Scope decision.** The test strategy lists Rust as out of scope while seven
Rust fixtures dominate three axes. Today a reader of the inventory cannot tell
that the C corpus is nearly clean on parameter types.

The recommendation is to **separate Rust from the primary roadmap**, not to
build a Rust ABI model now. The reasons: the DecBench failure taxonomy names
only C projects (mydoom, dexter, minipig, gzip); `decompiler-test-strategy.md`
already declares Rust out of scope; the Rust rows are a different problem
(niche-optimised enums, slices as pointer-length pairs, `bool` and `u8`
spelling, panic-unwind landing pads) whose fix shares almost nothing with the
C signedness and aggregate work; and 12,591 of 13,247 undefined reads are in
rustc lanes, so the Rust fixtures also dominate the def-use census. Concretely:
keep the seven fixtures, key every inventory axis and baseline by language,
report C and Rust counts separately, and open a Rust ABI track only when the
C axes are clean or a Rust corpus enters the benchmark. Rust as a leaderboard
target is a product decision this review does not make.

**Judge.** The `types` and `returns` axes, split by language; the PDB xfails;
the stripped-lane divergences.

## 6. Make declared prototypes authoritative in the product

**Evidence.** `src/ir/ast/decbench_render.rs:186-207` renders a DWARF or PDB prototype only
when the recovered arity and void-ness agree with it, and parameter names are
never applied; `tail_dispatch` in a `-g` object renders `long tail_dispatch(
unsigned int arg0, unsigned int arg1, int arg2)` where DWARF states `int
tail_dispatch(int tag, int a, int b)`, and every function in 03 renders
`arg0` beside DWARF-named locals (01 section 4, 03 all sections).

**Verified.** `readelf --debug-dump=info` on
`08_indirect_dispatch-gcc-O2.so` shows a `DW_TAG_subprogram` named
`tail_dispatch` whose `DW_AT_type` and first `DW_TAG_formal_parameter` (`tag`)
both resolve to `int`. The shipped output for that object is
`long tail_dispatch(unsigned int arg0, unsigned int arg1, int arg2)`. The
independent check is right that the authority mechanism exists on the
DecBench render path (analyst declarations outrank DWARF, DWARF contracts
lock recovery, `declared_prototype` overrides rendering); the observation is
that it did not hold here, and that parameter names are never applied.

**Build.** When the binary carries a declared prototype, render it: types,
names, variadic tail. The recovery fills gaps, it does not veto the
declaration. But authority is over what is rendered, not over what is
recorded: a disagreement between the declaration and the recovery is a fact
in its own right (an LTO build whose debug info predates the collapse, a
stale PDB, a genuinely wrong recovery), so keep both, with provenance, exactly
as the knowledge base already keeps `manual` beside `dwarf` beside `auto`.
Emit the conflict as a typed diagnostic in the function's health record and
feed it to the `types` axis so it stays measurable. Keep it out of deterministic
scored pseudocode by default; an explicitly annotated analyst render mode may
show it beside the signature. Blind override would hide the
binary-versus-debug-data disagreement that the LTO xfails exist to catch.

Chase the `tail_dispatch` case first: its apparent eligibility
should hold, but the declaration is still dropped; trace whether lookup, type
renderability, recovered arity, or recovered output classification rejects it.
Then prove authority across all
four entry points, every producer (DWARF, PDB, analyst), call-site
propagation, and the aggregate cases the renderer currently refuses. Keep measuring recovery quality in the
stripped lane (`O2strip`), which already exists for exactly this purpose.

**Judge.** Product track: the analyst-facing output never shows a worse
prototype than the binary carries. The strict `types` and `returns` generator
extracts the rendered signature through `decompiled_c`, so these axes should
improve when declared rendering becomes authoritative; require that movement
without regressing stripped recovery.

## 7. Add an expression idiom layer between SSA cleanup and rendering

**Evidence.** `(count + 7) / 8` and `count % 8` render as sign-fixup
ternaries over masks; `s * 10` renders as `(s + s*4) * 2`; `count < 1 ||
count > 16` renders as `(unsigned)(count - 1) > 15`; `-1` renders as
`0xffffffff` in an `int32_t` function (03 sections 3.2, 3.4, 3.5, 3.6). The
parity backlog's one-line finding is that the output "reads like lifted IR
where theirs reads like source". `cmp_fusion` and `named_constants` are the
first two idioms and both landed with measured wins.

**Build.** A single table-driven idiom pass over SSA expressions: signed
division and modulo by a power of two, magic-number multiplication for
division by a constant, strength-reduced multiplies, subtract-and-unsigned-
compare range checks, compound boolean masks, and literal spelling by
destination type. Each idiom is a rewrite with a stated precondition and a
fixture.

Do not hold every readability win behind the SSA migration. Destination-typed
literal spelling and one width-preserving range-check fusion can land now at
the existing typed render/`cmp_fusion` boundaries, with the same equivalence
tests, while the remaining idioms wait for the authoritative SSA-expression
layer. These two increments must stay narrow and must not create another value
identity system.

**Why this is tractable, and what makes it safe.** Idioms are expression-level
and move no blocks, so the goto-sinking GED loss (05 section 3) does not
apply and the byte-match metric rewards them directly. That is not what makes
them safe. Each idiom is a claimed semantic equivalence at a machine width,
and it is safe only when the equivalence is proved width-, signedness- and
overflow-aware: `(x + 7) >> 3` equals `(x + 7) / 8` only under the exact
sign-fixup pattern the compiler emitted; a magic-number multiply is a division
by `d` only when the multiplier and shift are the pair the width and `d`
determine; `(unsigned)(x - 1) < 15` is `1 <= x && x <= 15` only at the
operand's width. The `cmp_fusion` v1 regression (a 64-bit condition rewritten
as 32-bit, 11 lanes red, 05 section 3) is the precedent. So every idiom
carries its precondition in code, an exhaustive or randomised equivalence
test at the operand width (8- and 16-bit exhaustive, 32- and 64-bit
randomised with the boundary values), and the execution differential as the
end-to-end check.

**Judge.** Byte match on the DecBench sample; the readability census; the
`03_loop_shapes` and `102_duffs_device` fixtures.

## 8. Give the lifters a shared machine model and a standing capability census

**Evidence.** No lifter trait; three sets of width and flag helpers with
different names doing the same job; `cmp_flag_ops` in two ISAs; shared passes
re-encode ISA behaviour as `cc` gates (17 in `stack_locals.rs` alone);
`regview::Arch` has no ARM32 variant (01 section 8). ARM32 is 859 of the 1,909
arch fails (04 section 7). The roadmap records that three whole missing
instruction categories were found in three days by grepping mnemonics, that
this "belongs in a standing test, not in institutional memory", and that 28
silent-writer mnemonics with 1,130 occurrences are next (05 section 4).

**Build.** A `MachineModel` per target: register views and overlaps, flag
semantics, ABI (live-ins, return locations, clobbers, argument slots, stack
cleanup, tail-call shape), and silent writers. Lifters produce LLIR through it;
shared passes query it instead of matching `cc`. Then a test that decodes every
object in the fixture corpus, collects the mnemonic set, and fails when a
mnemonic reaches `Op::Unknown` or an `Intrinsic` without a documented
exemption.

**Judge.** Architecture track for the model (byte-identical output);
correctness track for the census (arch cells, the `SILENT_REGISTER_WRITERS`
list to zero).

## 9. Make verification fail closed, deduplicate the inventory, and consolidate the gates

**Evidence.** Every verifier logs, counts under an env var, or records and
continues; `UsedBeforeDefinition` is skipped for any function containing a
goto (01 section 5). The inventory substantially double-counts O2 rows (04 section 1).
CLAUDE.md lists, across nine bullets, gates that nobody runs during iteration:
the arch lanes, the def-use census, the structural tests, the fitness ratchet,
the three path-keyed allowlists; on 2026-08-31 seven tests were red on pushed
`master` for hours while every gate people actually type stayed green.

**Build.**

- Extend def-before-use to goto-bearing functions with a CFG walk over the
  AST's label graph; the functions being skipped are the ones with defects.
- Promote health findings (`BlockDropped`, `EdgeUnaccounted`,
  `UsedBeforeDefinition`, `if (0)` latches) from counters to failures in the
  fixture lane. This is about release evidence and the gates, not about the
  analyst's terminal: a best-effort body must still render for an analyst,
  with a typed refusal or health marker attached, rather than being
  suppressed. Fail closed on the claim, not on the output.
- Deduplicate `-O2` and `-O2strip.dwarf` in `gen_known_failures.py` so the
  inventory counts each defect once, and record the stripped lane separately
  where it actually diverges.
- One gate command with three profiles, so the whole matrix is never
  mandatory on every push and the gates that exist are never forgotten:
  - `fast` (minutes, the inner loop): build guard, `cargo test --features
    python-ext`, `dectest @smoke`, ruff, ty.
  - `default` (about an hour, before a push): `fast` plus `dectest @o0 @o2`
    with all four `--arch` targets, the def-use census, the structural lane,
    the fitness and allowlist tests, and the full Python suite.
  - `release` (hours, before a submission or a baseline refresh): `default`
    plus `scripts/feature-build-gate.sh`, the perf gate, and `--decbench`.
  Each profile prints what it did and did not run, so a green result names
  its own denominator. The 2026-08-31 incident was gates that existed and
  were not run, and the fix is one discoverable entry point with an honest
  scope line, not making everything mandatory.
- Add lane-keyed O2 closure/effect expectations (parity #8). Readability
  already covers GCC/Clang O0/O2; closure and effect expectations remain GCC
  O0-only.

**Judge.** The seven-red-tests-for-hours incident cannot recur; the inventory
counts are honest.

## 10. One pipeline for all four entry points, with a pass manager

**Evidence.** `decompile_range_at` never runs callee layout recovery, so the
same function by VA and by range gets different prototypes; `decompile_all`
and `decompile_many` re-run discovery and naming in their own loops (01
section 7). Pass ordering invariants live in prose comments and nothing checks
them; the same pass runs two to four times because earlier runs cannot see
later shapes (02, repeats table). `decompiler-middle-architecture.md` Phase 1
("all four entry points produce byte-identical output") and the roadmap's
`PipelineStage` / fingerprint items are open (05 section 2).

**Build.** One `decompile_function(session, va)` that every front door calls.
A pass manager where each pass declares its preconditions (pre-SSA,
post-naming, structured-only, requires-types) and the manager checks them,
plus a fixpoint driver for the settle loops in place of hand-repeated calls.
Pass-firing statistics come for free and feed recommendation 3's gate. A
deterministic pipeline fingerprint and function-parallel scheduling become
possible only after this exists.

**On byte-identical output.** The contract is: the same function, the same
session, and the same analysis budget produce the same bytes regardless of
which entry point was called. A lower-context, lower-latency mode is
legitimate, and `decompile_range_at` may be meant as one, but today it is an
accident of which function was called rather than a declared contract. Make
the budget an explicit parameter of the one pipeline (callee-analysis depth,
CFG bounds, type recovery on or off), record the budget used in the output
beside the existing `Completeness` reasons, and then the test is: equal
budgets give equal bytes, and a lower budget declares itself. Whether the
range entry point should default to the lower budget is a product decision;
that it currently differs silently is a defect.

**Judge.** Architecture track: byte-identical output across all four entry
points at equal budget over the fixture corpus, then the repeat count in 02
falling.

## Decision points raised on review, and the answers taken here

Six questions were put to the recommendations after the first draft. The
answers below are recorded where they change a recommendation.

1. **Is Rust ABI recovery in scope?** Recommended no, for now: separate it
   from the primary roadmap and key every axis by language (recommendation 5).
   Whether Rust becomes a leaderboard target is a product decision.
2. **Does "one SSA construction" mean literally one?** No. One authoritative,
   versioned SSA state with explicit invalidation and repair; recomputation
   is legitimate when a transform declares what it changed (recommendation 2).
3. **Which MIR consumer gets the trial?** The path-sensitive
   `UsedBeforeDefinition` check on goto-bearing bodies, with a two-day
   budget, a unique-value requirement, a 10% cost ceiling and a deletion
   threshold (recommendation 3).
4. **Are declared prototypes absolutely authoritative?** Authoritative for
   rendering, not for the record: keep both facts with provenance and emit
   the conflict as a typed diagnostic (recommendation 6).
5. **Must all four entry points be byte-identical?** At equal analysis budget,
   yes. A lower budget is legitimate when it is an explicit parameter recorded
   in the output, not an accident of the entry point (recommendation 10).
6. **One gate command for everything?** One command with `fast`, `default`
   and `release` profiles, each printing its own denominator
   (recommendation 9).

## What this review did not do

- It did not run DecBench or Joern, and it did not re-measure any baseline.
  Every count is from committed JSON or from the documents named.
- It did not chase why `tail_dispatch`'s declared prototype was dropped
  (recommendation 6).
- It did not measure how many of the 715 goto rows each shape in
  recommendation 1 would close; that is the first thing the shadow-mode
  structurer should report.
