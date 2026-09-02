# Decompiler plan, 2026-07-27

> **Kind:** record · **Date:** 2026-07-28

> **Status, 2026-07-28:** Historical evidence and remaining backlog, not a live
> implementation checklist. Upstream already supplied the loop-form and canonical
> `Expr::Select` work described in Phase A. The separately useful bounded-dispatch,
> x86 flag, pass-pipeline, region-ownership, and fail-closed fixture-gate work is on
> `master` in `39d1b44..2f32318`. The full pinned 56-lane/623-function differential
> matrix completed with zero regressions. Re-run DecBench/Ghidra/angr measurements
> before reprioritising the still-relevant total-structuring and value-model items.

Derived from `docs/analysis/decompiler/2026-07-27-three-way-roundtrip-diary.md` — a
function-by-function `C -> binary -> C` comparison against Ghidra 11.4.2 and angr
9.3.0 over the 14-program DecBench corpus at gcc/clang `-O0`, plus source studies of
both competitors' decompilers.

**This supersedes the phase ordering in `value-model-root-cause-and-plan.md`.** That
document made the value model the keystone and put region ownership last. The
measurements say the reverse, and say it in two independent ways:

* control-flow artifacts are **~48 % of our emitted control-flow statements**, while
  the value-model symptom the plan predicted (bare-temp assignments removable by
  folding) is **9 %** of our assignments;
* 49 % of the 209 fixture failures already sat in structuring by first-firing
  instrument.

## The one-line diagnosis

> Our expression and idiom recovery is competitive with both leaders. Essentially all
> of our distance is **control-flow shape**, and most of that is three named,
> individually cheap defects.

Measured, 60 functions, control-flow statements per function: **glaurung 5.2, Ghidra
3.1, angr 2.9.** The excess decomposes as 57 extra `break`, 36 extra `goto`, 54 extra
`if`.

---

## Phase A — the loop forms (highest value per unit of work)

**Evidence:** we emit `while (1) { if (!c) break; ... }` for **19 of 19** loops in the
corpus. Ghidra emits `for` 30 times, angr 34. This is a *representational* gap:
`Region` (`src/ir/structure.rs:28`) has no `DoWhile` and no `For`, so those forms are
unreachable regardless of what the structurer decides.

| # | Task | Acceptance |
|---|---|---|
| A1 | Add `Region::DoWhile { body, cond, .. }`. Detect a latch whose condition sits at the *bottom*. | `loops:count_bits` emits `do { ... } while (x);` |
| A2 | Restore `While { cond }` for the head-test case. Re-open `3ef32ae`: its soundness claim was later found false as stated, and the doc that kept it says "a soundness argument that is only tested at the predicate level is not tested". Require a **fixture that actually misbehaves** before keeping the hoist. | `loops:factorial` emits `while (n > 1)`; the `str_len` infinite-loop fixture still passes |
| A3 | Add `for`-promotion as a post-structuring pass (angr's `LoopSimplifier`): if every continue-prelude ends with the same non-control-transferring statement it becomes the iterator; if the loop's predecessor ends in an assignment to the same variable it becomes the initializer. | `arrays:sum_array` emits `for (i = 0; i < n; i++)` |

**Expected:** removes most of the 57 excess `break`s and a large share of the 54
excess `if`s.

**Correction (2026-07-27, after re-checking).** An earlier draft of this plan claimed
loop form was "the whole gap" on `arith`, `checksum`, `fixedpoint` and `loops`. That
is wrong for `arith`, which **contains no loop at all** — verified by
`grep -cE '\b(for|while|do)\b' tests/decbench_corpus/src/arith.c` returning 0. The
refined and verified attribution:

| program | loops? | our GED | cause |
|---|---|---|---|
| `loops` | 3 | 3.33 | loop form |
| `checksum` | 2 | 4.00 | loop form |
| `fixedpoint` | 1 | 1.33 | loop form |
| `structs` | 0 | 0.00 | (we tie both competitors) |
| `arith` | **0** | 1.00 | **ternary — see A4** |
| `branches` | **0** | 7.00 | **ternary — see A4** |

Every loop-containing program scores >0 for us and 0.00 for both competitors, and the
only no-loop program with no other defect (`structs`) ties at 0.00. The correlation is
clean — but it does not extend to `arith`/`branches`, and asserting that it did was
the same extrapolation-from-one-case this repository's own docs warn about.

**Size:** small. A2/A3 need no SSA and no new analysis.

### A4 — ternary recovery (promoted here from a lower rank; measured cost 8.00 GED)

Two sub-cases with very different costs:

**A4a — render `Op::Ite` as a ternary or a one-armed `if`. Pure rendering, very cheap.**
`arith:signs`, source `(a < 0 ? -a : a)`:

```c
ghidra:    iVar1 = -a;  if (0 < a) { iVar1 = a; }        // one-armed, 2 nodes
glaurung:  var2 = t0;   if (t0 < 0) { var3 = var0; }
                        else        { var3 = var2; }      // two-armed, 3 nodes
```

We already lift `cmovcc` to `Op::Ite`; the readiness doc made that change knowingly and
recorded that it "renders as a two-armed `if` instead of a one-armed one". That
rendering choice costs the entire `arith` 1.00. No analysis needed — `Op::Ite` is a
three-input select and should render as one.

**A4b — collapse an if/else diamond whose arms assign the same variable.**
`branches:classify`, source `if(a>b) return a-b; else if(a<b) return b-a; return 0;`:

```c
angr:      return (a0 <= a1 ? (a0 < a1 ? a1 - a0 : 0) : a0 - a1);   // ONE statement
glaurung:  nested if/else through a `ret` temporary                  // seven
```

angr's `ITERegionConverter` (`ite_region_converter.py:56-185`) gates this on the join
block having a **phi whose two operands are exactly the two assigned values** — that is
what makes it sound, and we have no phis on stack slots. But a structural AST match
("both arms assign the same destination and nothing else") covers the common case
without SSA, and can be tightened later.

| # | Task | Acceptance |
|---|---|---|
| A4a | Render `Op::Ite` as `d = c ? x : y` (or a one-armed `if`) | `arith` GED 1.00 -> 0.00 |
| A4b | Collapse same-destination if/else diamonds into a ternary | `branches` moves toward angr's 5.50 |

---

## Phase B — total structuring by goto virtualization

**Evidence:** 36 `goto`s against Ghidra's **0** and angr's 4 (31 vs 0 and 0 on the loop
fixtures). `Region::Unstructured` is a dead end; both competitors instead make forced
progress.

**Two independent implementations converged on this**, which is the strongest evidence
in the study:

* Ghidra — `collapseAll` (`blockaction.cc:1877-1893`) loops
  `while (isolated_count < graph.getSize())` calling `selectGoto()` (`:1260-1277`),
  which marks one edge unstructured so `ruleBlockGoto` must fire next pass.
* angr — `phoenix.py:188-238`; `_last_resort_refinement` (`:3021-3141`) virtualizes one
  edge into a `goto`.

**And Ghidra has only ELEVEN collapse rules** (`blockaction.hh:209-219`) — comparable
to our three detectors. *The pattern catalogue is not the difference.* The difference
is that neither system can get stuck.

The algorithm, from angr's Phoenix (`phoenix.py:188-238`, `_last_resort_refinement`
at `:3021-3141`):

```
while the region graph has more than one node:
    progress = try every schema (acyclic, then cyclic)
    if not progress:
        pick one edge by heuristic, convert it to a goto, delete it   # forced progress
        if no edge can be cut: dissolve the region into its parent
```

Termination is structural — each forced step removes an edge. We already have
`Region::Goto` (`structure.rs:77`) for exactly this purpose; it is just never used as
a fallback.

| # | Task | Acceptance |
|---|---|---|
| B1 | Turn the structurer into a fixed-point loop over a **collapsing** graph rather than a DFS with a `visited` set. The `visited` set is a cursor, not a graph transformation, and is the mechanism behind the `BlockDropped`/`BlockDuplicated` findings `structure_accounting.rs` already reports. | `structure_accounting` reports zero `BlockDropped` / `BlockDuplicated` corpus-wide |
| B2 | Goto-virtualization fallback, ordering candidate edges by (i) fewest sibling in-edges, (ii) edges straight to a `return`. Skip angr's post-dominator-counting heuristic — it needs repeated dominator computation for modest gain. | `Region::Unstructured` is never constructed; `fsm` at clang:O0 loses its goto debris |
| B3 | Region identification as a prior pass: loops innermost-first, each collapsed to an atom, then acyclic SESE by dominance frontier. This is what keeps the schema catalogue small enough to be complete. | the three previously-reverted structuring fixes can be re-attempted without breaking a sibling shape |
| B4 | **Edge flags computed once by a Tarjan pass** — `{goto, back, loop_exit, irreducible}` — with every detector consulting them instead of `visited`. Ghidra's `block.hh:108-118` + three derived predicates at `:336-345`. `visited` is currently doing double duty as "already emitted" and "do not re-enter", which is where the sibling-arm defects live. `src/ir/cfg_edges.rs` already exists as a home. | irreducible CFGs stop being a special case; `detect_*` stops re-deriving edge meaning |
| B5 | **Structure a throwaway COPY of the CFG** (Ghidra `blockaction.cc:2177`, `buildCopy`). Rules may then delete edges and *move* nodes (`identifyInternal`, `block.cc:940-963`), so block conservation is structural rather than audited. | `structure_accounting.rs`'s `BlockDropped`/`BlockDuplicated` become unrepresentable rather than merely detected |

**Expected:** removes the 36 excess `goto`s; unblocks `fsm` (the outstanding
behavioural regression, whose guard and arms are now correct C but whose structure is
debris); attacks the 49 % of fixture failures in bucket B.

**Size:** B1+B2 medium; B3 is the architectural piece. **B2 is worth doing before B3**
— it is small and converts catastrophic output into one extra `goto`.

---

## Phase C — the validation harness (do this *with* Phase B, not after)

**Evidence:** three prior structuring fixes were each reverted for breaking a sibling
shape, and this session shipped a fail-open jump-table bug and a GED regression that
took a full control run to attribute.

angr's `StructuringOptimizationPass` (`optimization_pass.py:499-568`) validates every
speculative rewrite by **re-running the structurer and counting**: goto count, label
count, and loop kinds ranked `for > while > do-while`, with automatic rollback.

| # | Task | Acceptance |
|---|---|---|
| C1 | A `GotoManager` + `ControlFlowStructureCounter` over the recovered region tree. | per-function goto/label/loop-kind counts available to any pass |
| C2 | A pass wrapper: snapshot, apply, re-structure, compare, roll back if worse. | a pass that increases gotos cannot land |
| C3 | Wire the counts into `tools/dectest.py --full` so a scoped run reports them. | structural quality is visible in 3 seconds, not 37 minutes |

**Why now:** without it every Phase B heuristic is a coin flip evaluated only
corpus-wide, which is exactly how the last three attempts failed.

---

## Phase D — flags, finished properly

**Evidence:** four independent discoveries of one gap (`neg` defined none, `test`
three of four, `cmovcc` mis-modelled, and this session: **`sub` and every other ALU
op defined none at all**). 27 flag assignments still leak into rendered C; neither
competitor emits any.

**Both competitors independently eliminated the concept.** Ghidra models x86 flags as
ordinary 1-byte registers holding boolean expressions (`ia.sinc:38-41`, `:2142-2167`),
with a single `cc` subtable exporting the branch condition (`:1523-1538`), and
reassembles comparisons by term rewriting (`RuleSborrow` `ruleaction.cc:3338`,
`RuleLessEqual` `:2223`, `RuleBoolNegate` `:5446`). The confirming grep over all ~150
decompiler sources returns **nothing**:

```
grep -rn '"ZF"\|"CF"\|"SF"\|"OF"\|zeroflag\|carryflag' decompile/cpp/*.cc *.hh
```

angr reaches the same place differently (`ccall_rewriters/amd64_ccalls.py`): the
arithmetic records a deferred `(op, dep1, dep2)`; the branch resolves
`(condition_code, op)` through a table into a real comparison with correct widths.

Our `Ule`/`Slt`/`Sle` variants exist *because* our lifter must pre-fold multi-flag
conditions itself — we moved `RuleSborrow`'s job into the lifter, once per instruction
pattern, per architecture.

| # | Task | Acceptance |
|---|---|---|
| D1 | Version flag VRegs in SSA. Alone this turns the backward AST search into a def-use lookup and makes the existing derived predicates sound. | `14_flag_effects` green; no branch reads a flag from a non-dominating definition |
| D2 | Audit the flag-setting mnemonic *family* rather than one at a time — `add`, `and`, `or`, `xor`, `shl`, `shr`, `sar`, `imul`, `inc`, `dec`, `neg`, `test`. | a fixture per family; `verify_defs` no longer excludes `VReg::Flag` |
| D3 | Replace `Flag::{Ule,Slt,Sle}` (derived predicates masquerading as status bits) with the deferred record + lookup table. | no flag identifier appears in rendered C |

**Size:** D1 small and high value; D3 is the real fix and is medium.

---

## Phase E — aggregates, and the type ceiling

**Evidence:** angr synthesizes a **recursive struct** from access offsets with no
debug info (`linkedlist:list_sum`), rendering `i->field_0` / `i->field_8`. We emit
`*(int *)(p + 8)`. This is our `structs` 0.25 / `linkedlist` 0.50.

Important correction to prior planning: the earlier estimate put our inference ceiling
at 0.917 (gcc:O0) *assuming aggregates are unrecoverable*. angr demonstrates they are
not. Also note **Ghidra's type lead is largely benchmark artifact** — it reads the
DWARF that is DecBench's ground truth; stripped, it scores 0.000 on `structs`, below us.

Cheap, individually-measured wins first (each with a cited defect):

| # | Task | Size |
|---|---|---|
| E1 | `types_recover.rs:225` keeps only the *last* store per spill slot, so a re-stored parameter loses its pointer-ness. Keep the first, or all. | one line |
| E2 | `Op::SExt`/`Op::ZExt` have no arm in `tag_value_regs`, so `movslq %edi,%rdi` — the only evidence a -O2 parameter is `int` — is discarded. | two match arms |
| E3 | Pointer-ness does not cross `Op::Assign` copies; gcc -O2 opens with `mov %rdi,%r8` and dereferences the copy. | one rule |
| E4 | Field-offset clustering: group accesses off one base by offset and width, synthesize a struct, render `->field_N`. | medium |

Do **not** port retypd. angr itself disables its solver above a constraint threshold.
The right foundation is keying types on **SSA value** rather than register name, which
`value_number.rs` already argues for.

---

## Phase F — hygiene, cheap and visible

| # | Task | Evidence |
|---|---|---|
| F1 | Suppress cast noise: `(unsigned long)((unsigned int)(arg1))` on nearly every operand | every captured function |
| F2 | Emit `case` labels in ascending order | `switch_jt:dispatch` emits 7,6,5,4,3,2,0,1 |
| F3 | Drop dead trailing assignments (`ret = local_4;` before `return local_4;`) | `strops:str_len` |
| F4 | Adopt angr's jump-table reject list: shape check, mapped-section check, all-entries-readable, decode-check the target, and reject counts of exactly 1 / 0x100 / 0x10000 | our fail-open bug this session |
| F5 | **Refresh `tests/decbench_corpus/baseline.json`.** It is 9 commits stale and concealed a 24 % GED regression for an entire session. | control run: true master 12.678 vs recorded 10.238 |

**F5 is not optional and should be done first** — nothing downstream can be trusted
against a baseline that does not describe the code.

---

## Ordering

```
F5  (refresh the baseline — everything else is unmeasurable without it)
 |
A   (loop forms + A4 ternary) <- biggest measured win, smallest work, no dependencies
     A4a is pure rendering and could land today
 |
C1,C2 (validation harness) <- makes B safe
 |
B4  (edge flags)           <- prerequisite for B2 being correct
B2  (goto fallback)        <- converts catastrophic output into one goto
 |
D1  (version flags in SSA) <- small, fixes a soundness bug
 |
B5,B1,B3 (structurer on a collapsing copy) <- the architectural piece
 |
E1-E3, F1-F4 (cheap, parallelizable at any point)
 |
D3, E4 (the remaining architectural items)
```

**B4 + B2 + B5 are one project and should land together.** B4 gives the rules
something reliable to consult, B5 makes forced edge-removal safe, and B2 is the
escape hatch itself. Doing B2 alone against the current `visited`-set driver would
force gotos while blocks silently vanish.

---

## Submission readiness — measured, 2026-07-27

**Where we would enter today: last of three on all three metrics.**

| metric | glaurung | ghidra | angr | our rank |
|---|---|---|---|---|
| GED (lower better) | 12.732 | 11.497 | **9.926** | **3 of 3** |
| type_match | 0.685 | **0.903** | 0.694 | **3 of 3** |
| byte_match | 0.198 | **0.300** | 0.274 | **3 of 3** |

That is the honest position and it should be stated to ourselves before it is stated
to a reviewer. Two mitigating facts, neither of which changes the ranking:

* Ghidra's `type_match` is DWARF-assisted (the corpus is `-g`, and DecBench's ground
  truth *is* that DWARF). Stripped, it scores 0.000 on `structs` against our 0.250.
* We beat both on `switch_jt` (23 vs 42 vs 45), which no aggregate shows.

### Headroom, per program, GED at -O0 against the best competitor

| program | ours | best competitor | gap |
|---|---|---|---|
| statemachine | 40.50 | 15.00 | **25.50** |
| matrix | 13.00 | 3.00 | **10.00** |
| sort | 8.25 | 1.50 | 6.75 |
| linkedlist | 4.75 | 0.00 | 4.75 |
| arrays | 5.67 | 1.00 | 4.67 |
| checksum | 4.00 | 0.00 | 4.00 |
| recursion | 6.00 | 2.50 | 3.50 |
| strops | 5.50 | 2.00 | 3.50 |
| loops | 3.33 | 0.00 | 3.33 |
| branches | 7.00 | 5.50 | 1.50 |
| fixedpoint | 1.33 | 0.00 | 1.33 |
| arith | 1.00 | 0.00 | 1.00 |
| | **118.82** | **72.50** | **46.32** |

Note `statemachine` is **40.50 with this session's dispatch work**, against 31.00 on
master. Recovering its jump table is correct — the arms genuinely enter the CFG now —
but the structurer then produces goto debris, so the metric got worse. **Phase B is
what redeems that change**, and until B lands, the dispatch work is a net GED cost on
that one program (offset by `switch_jt` −19 and two behavioural fixes).

### Recommendation on timing

**Do not submit before Phase A + A4.** They are the smallest work in this plan with the
largest measured effect, they are pure additions with no architectural risk, and they
attack the programs where both competitors score a perfect 0.00 and we do not. Entering
last-of-three on every metric when three of the causes are known, named and cheap would
be a worse use of the one first impression we get.

### On the agentic backend

`Noelo-Lab/decbench#43` (2026-07-27) documents Claude Code recalling bzip2's
`fallbackSort` **and its version** from raw assembly in three `objdump` calls, with no
lookup. The maintainer is actively deciding policy — string encryption, cheating flags,
possibly disallowing agents entirely.

**Submit `glaurung_raw.py` alone.** It is deterministic, offline, and outside that
question entirely; it is also where all of the engineering in this plan lands. Hold
`glaurung_agentic.py` until the benchmark's policy settles, or it risks being *marked*
rather than judged. Also note mitigation idea #1 (encrypt all strings) would neuter
`strings_fold` on the benchmark — equally for everyone, but it moves our `byte_match`.

---

## What NOT to do

* **Do not build general expression folding first.** It is the obvious move and the
  measurement says it is 9 % of our assignments. It matters for *readability* (angr
  declares 0.1 variables per function to our 3.7) but not for the GED gap.
* **Do not port claripy, VSA, sympy, or retypd.** angr's own fast paths avoid its
  solver for the common case, and it caps or disables the expensive analyses. Take the
  algorithm shapes, not the engines.
* **Do not chase `type_match` against Ghidra's DWARF-assisted number.** The honest
  comparison is against Ghidra stripped, where we are already ahead on `structs`.
* **Do not write another phase plan before landing Phase A.** This repository has six
  overlapping design documents and one landed slice; the ratio is the problem.
