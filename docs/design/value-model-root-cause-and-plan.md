# The value model is the root cause: diagnosis and phased plan

**Status:** proposed
**Snapshot:** local `master` at `d6144a7`, 2026-07-26
**Companion:** `decompiler-middle-architecture.md` describes the target architecture.
This document is the *data-structure diagnosis* underneath it, plus an ordered plan.

## 0. The event that forced this

Today's session improved the execution differential from 36% → 84% → **92%** at
gcc -O0, and simultaneously regressed **~25 of 56 DecBench metric cells with none
improving**:

| cell | GED before | after |
|---|---|---|
| `matrix:gcc:O0` | 3.0 | **15.0** |
| `matrix:clang:O0` | 3.0 | **11.0** |
| `sort:gcc:O0` | 3.5 | **10.0** |
| `strops:gcc:O0` | 2.0 | **6.0** |
| `loops:gcc:O0` | 0.67 | **3.33** |
| `statemachine:gcc:O2` | 14.0 | **29.0** |
| `recursion:gcc:O2` | 123.0 | **150.5** |

plus `byte_match` down in six cells. **Nothing improved.**

It was invisible because lane 3 of `scripts/decbench-local-gate.sh` — the only gate
that scores GED / type_match / byte_match — SKIPPED on every run: `DECBENCH_DIR` was
unset because the checkout lived in a *session scratchpad* that had been reaped. The
script prints `Skipping is a gap, not a pass`. I read that line, quoted it in a
document, and kept shipping semantic changes for a whole session anyway.

So there are two failures, and only one of them is architectural:

* **Process:** a behavioural gate was treated as a full gate. "Fixture matrix green"
  was reported as "no regressions" when it only ever meant "no *behavioural*
  regressions". That is fixed by making the metric lane non-skippable (Phase 0).
* **Architecture:** every fix that improved behaviour ADDED graph structure, because
  the only way to fix these defects in the current representation is to add
  statements. That is the subject of this document.

The second point is the important one. It was not bad luck that correctness and GED
moved in opposite directions. **In this representation, they are forced to.**

## 1. The one defect: `VReg` is an overloaded key

```rust
enum VReg { Phys(String), Temp(u32), Flag(Flag) }
```

This single type is used as **five different things at once**:

| what it is used for | how it is encoded | who reads it that way |
|---|---|---|
| value **identity** | the string, mangled to `rax#2` | `value_number`, `insert_phi_copies` |
| **storage** | the register spelling | `stack_locals`, renderer |
| **width** | implied by spelling (`eax`=4, `rax`=8) | `widen`, `types_recover` |
| **role** | the name (`ret`, `argN`, `local_N`) | `naming`, `call_args`, AST lowering |
| **kind** | which variant, plus `Flag`'s own overloading | AST condition matching |

Because those five collapse into one field:

1. **Any pass needing one of them must parse or pattern-match a name.** Identity
   becomes a string operation (`format!("{canon}#{version}")`, `n.starts_with("var")`,
   `parse_arg_index(n)`).
2. **Any pass changing one silently changes the others.** Canonicalising `eax`→`rax`
   to keep def/use aligned destroys the width. Hence the pipeline keeps *two*
   LLIRs alive — canonical for values, raw for widths — and reconciles them by name
   remapping afterwards.
3. **Facts that have no name cannot be represented.** A function's return type, a
   frame base, an address-taken object, "this flag is undefined" — none has a
   spelling, so none exists.

Everything below is a consequence.

### 1.1 Trace: every failure this session, to the same cause

| failure | surface symptom | the actual mechanism |
|---|---|---|
| `matmul` (void) emits `long ret;`, assigns it **inside the outer loop**, `return ret;` | +3 graph nodes in the worst position; `matrix` 3.0→15.0 | `eax` is scratch for the loop compare. `keep_bare` decides "this def reaches a return" **by name+version**, so it stays spelled `ret`; AST lowering then synthesises `return ret` **by matching that name**. The function's void return type is not part of the value model, so nothing can contradict the name. §2.1's "returned values confused with scratch uses", exactly. |
| `dec_loop` recovers `int(signed char, long, int)` for `int(int)` | wrong arity + narrowing; damages `type_match` | width is read off the *spelling*. `test $0x1,%dil` touches the 8-bit view, so a narrow **use** rewrites the declared **parameter**. Width is a property of the string, not the value. |
| 10 polarity regressions on the flags branch | `cmp_signed`, `ternary`, `sc_or` … all fail | the condition algebra was right. A composite arrived as `Temp` instead of `Flag`, and AST lowering recognises conditions by `Expr::Reg(Flag)` **shape**. Same boolean, different spelling → different behaviour. |
| `Flag::{Ule,Slt,Sle}` | `test` can't supply `Sle`; `jle` reads a stale one | `Flag` is a set of *names*, so a *condition* (`ZF|(SF!=OF)`) is stored where a *flag* goes. The composition is frozen into the producer. |
| `rbp - 32` passed as a `this` pointer → SIGSEGV | 6 functions, all -O0 lanes fail / -O2 pass | storage **is** identity, so `rbp` renders as an ordinary C local, declared and never assigned. There is no `FrameBase`, because there is no field in which it could differ from a register. |
| `signs`: `if (sf)` before `sf` is assigned; empty `if`/`else` arms | returned uninitialised stack | SSA is a *sidecar*: phis exist in `SsaInfo` but not in the IR, so a phi result is a name nothing defines. |
| `test` defines 2 of 6 flags; `add`/`sub` define 0 | -O2 branches read stale flags; `dec_loop` infinite loop | flag effects are hand-written per mnemonic. No type forces totality, so *absent* and *no effect* are the same. |
| `bsearch_i`: epilogue hoisted into the loop | loop runs once; trailing `return` lost | region ownership is `visited: HashSet<usize>` — traversal state, not a computed partition. |

### 1.2 Why fixing symptoms *must* inflate GED

This is the part I got wrong all session, and it is structural, not incidental.

When identity is a name, the only way to give a value a definition is **to emit a
statement that assigns that name**. So:

* SSA has no phi node → out-of-SSA becomes *copy insertion*, adding `dst = incoming`
  per predecessor. With first-class phis it would be a *coalescing* problem that emits
  nothing.
* A width is wrong → fix it by emitting a **cast**. With a typed value the width is
  a field, and rendering chooses whether a cast is needed.
* A flag composite is missing → fix it by emitting **flag arithmetic**
  (`sf = …; of = …; if (zf | (sf != of))`). With a typed `BoolId` carrying provenance,
  the renderer reconstructs `a <= b`.
* An undefined read → fix it by emitting an **initialisation**.

Every one of those is +N graph nodes. GED counts graph nodes. **So in this
representation, correctness is bought with GED, at a fixed exchange rate.** ~25
regressed cells is that exchange rate applied to a session's worth of fixes.

The corollary is the strategic point: **we cannot beat Ghidra or angr on GED by
continuing to fix correctness this way.** Not "it will be hard" — the arithmetic
forbids it. Each fix moves us further from the source shape.

### 1.3 The second, independent defect: ownership is traversal state

`structure.rs` builds the region tree with a global `visited: HashSet<usize>` and a
sequence of shape recognisers tried in order. Ownership of a block is therefore
**whichever recogniser reached it first**. Shared joins, rotated loops, switch arms
inside loops, and early exits all compete for the same blocks.

This is why `bsearch_i` puts the shared `-O0` epilogue inside the loop, and why my
attempted fix (requiring both arms to forward-reach the join) *reduced* structure
quality: declining a shape does not produce an honest `goto`, it produces an
unstructured `Seq` whose implied edges are a different lie. Findings went 3 → 9.

Ownership must be a **computed partition** derived from dominator/postdominator trees,
loop forests and SESE boundaries — not a side effect of walk order.

### 1.4 The third: effects are optional, not total

Flag effects, call effects, and CFG completeness are all "whatever the lifter happened
to write". There is no type that forces exhaustiveness, so **absence is
indistinguishable from "no effect"**:

* `add` defines no flags → a following `jle` reads a stale one, silently.
* discovery fails to resolve a jump table → the case blocks simply are not in the CFG,
  and structural accounting cheerfully proves the region matches the (incomplete) CFG.
* an unknown instruction → `Op::Unknown`, and dataflow continues as if nothing happened.

`Defined(expr) | Preserved | Undefined` is not a nicety; without the third case there
is no way to say "reading this is a bug", so a stale read is indistinguishable from a
correct one.

## 2. What must become true

1. **Identity is opaque.** A `ValueId` with no parseable content. Names become
   presentation metadata attached at rendering, never consulted by a pass.
2. **Width is a field, not a spelling.** `MachineSort = Bool | BitVec(width)` on every
   value. Canonicalisation cannot destroy it, so the dual raw/canonical LLIR goes away.
3. **Phis are instructions.** Out-of-SSA becomes coalescing, which emits nothing.
4. **Conditions are typed booleans with provenance.** A branch consumes a `BoolId`;
   the renderer can reconstruct `a <= b` from provenance instead of printing plumbing.
5. **Storage is separate from identity.** `RegisterView | StackObject | AbiInput |
   FrameBase | Temporary`. A frame base is then *unrenderable* as a C local — not by a
   verifier rule, but because no code path can spell it.
6. **Effects are total.** Every flag, every call, every terminator has an explicit
   effect including `Undefined`, and consumers fail closed.
7. **Region ownership is a computed partition** from graph boundaries.
8. **Every stage returns artifact + trust status.** A failure degrades one function to
   an honest fallback; it never becomes plausible C.

## 3. Phases

Ordering rule: **nothing that changes rendered output lands before the metric gate can
see it.** That is why Phase 0 exists and is not optional.

### Phase 0 — make the regression visible and stop the bleeding

*This phase writes no decompiler code.*

| # | task | acceptance |
|---|---|---|
| 0.1 | Point `DECBENCH_DIR` at the durable checkout (`/nas4/data/workspace-infosec/decbench`) and record it in the local gate + docs | `scripts/decbench-local-gate.sh` runs lane 3 without env setup |
| 0.2 | Make a **skipped** metric lane a hard failure, not a printed note | the gate cannot pass with lane 3 skipped |
| 0.3 | Bisect the ~25-cell GED regression across `a1a8a87..d6144a7` — attribute each cell to a commit | a per-commit attribution table; no cell unexplained |
| 0.4 | For each attributed commit decide: keep (correctness worth the GED), revert, or fix cheaply. Record the decision and its evidence | every regressed cell has a decision with a reason |
| 0.5 | Add the round-trip differential as a ratcheted gate lane (currently a tool a human runs) | a correctness regression fails a gate |
| 0.6 | Install Ghidra; produce a 3-way per-lane table (glaurung / angr / ghidra) | readiness doc leads with the Ghidra column |

**0.3 and 0.4 are the immediate work.**

#### 0.3 result — bisected, and my first two hypotheses were both wrong

I guessed the phi copies. Then I guessed the phantom `ret`. The bisect says neither.

Comparing `a1a8a87` (baseline) against `d6144a7` on `matmul`:

```c
// a1a8a87                              // d6144a7
local_10 = 0;                           local_10 = 0;
ret = (unsigned long)(local_10);        while (1) {
while ((local_10 < arg3)) {                 ret = (unsigned long)(local_10);
                                            if ((arg3 <= local_10)) { break; }
```

The phantom `ret` is present in BOTH — it predates the session. What changed is the
**loop form**, and the cause is `3ef32ae`, my own loop-header hoist "soundness" fix.
`matmul` has three nested loops; each pays `while(1)` + `if` + `break` instead of
`while (cond)`. `loops`, `sort`, `strops` at -O0 are the same shape. `sum_to` and
`factorial` regressed identically and have no phantom-`ret` involvement at all.

**And the soundness claim it rests on is false.** From the doc comment I wrote:

> `t` never changes and the loop spins forever.

That holds only if the hoisted copy stays a separate statement. Copy propagation folds
it INTO the condition — which the *previous* comment said explicitly — giving
`while (i + 1 < n)`, re-evaluated every iteration. My RED test asserted that the
*predicate* returned `true` for that shape; it never demonstrated a hanging program. I
proved a predicate permitted something I believed was unsound, then wrote "Declining is
cheap." It cost ~25 metric cells.

I also claimed it bought no correctness, on the grounds that `loops` never appears in
the pass→fail list. **That was checking the wrong fixture family.** Removing the
requirement regresses `12_loop_rotation:gcc:O2:find_first_set` pass→fail. So the trade
is real: **7 fully-recovered GED cells (+3 partial) against 1 behavioural pass.** Not a
pure loss, and not a clean revert.

The genuine `str_len` infinite loop was fixed by `a6d6da0` (introducing the hoist with
its `Deref` / self-reference exclusions). `3ef32ae` added body-invariance *on top*, and
the experiment on branch `hoist-revert-experiment` removes exactly that requirement —
keeping the `Deref`, self-reference and effect exclusions — to measure whether it was
ever necessary.

**The lesson generalises past this bug.** A soundness argument that is only tested at
the predicate level is not tested. The end-to-end behaviour is the claim; the predicate
is an implementation of it. Every "this would be unsafe" assertion in this codebase
needs a fixture that actually misbehaves, or it is a guess with a comment attached.

#### 0.3 measured outcome — the tightening is a MINORITY cause

Removing only the body-invariance requirement (branch `hoist-revert-experiment`) and
re-running all 56 cells:

| | cells |
|---|---|
| fully recovered to baseline | **7** — every `loops` cell, plus `linkedlist:gcc:O2` |
| partially recovered | **3** — `recursion:gcc:O2` 150.5→143.5, `clang:O2` 12.0→10.0, and its byte_match |
| unchanged | **18** — including `matrix:gcc:O0` still **15.0**, `sort:gcc:O0` 10.0, `strops:gcc:O0` 6.0, `statemachine:gcc:O2` 29.0 |

So `3ef32ae` explains the `loops` family and part of `recursion`, and explains NONE of
the worst cells.

**I overreached again.** Having measured `matmul`'s loop form I wrote "matrix has 3
nested loops, each paying +3 nodes — `loops`, `sort`, `strops` at -O0 are the same
shape." The first clause was measured; the generalisation was reasoning, and the data
says it is false. That is the third extrapolation-from-one-case in this session, and the
pattern is now the finding: **a confirmed mechanism in one function is evidence about
that function only.** Attribution requires measuring each cell, not recognising a shape.

Remaining candidates for the other 18, to be bisected one at a time and NOT reasoned
about:

* `ea9d4b8` — structural accounting. Nominally diagnostic, but it moved typed CFG edges
  *into* `Cfg`, which the structurer now consumes; that can change region choice.
* `0cf6ff6` — extension target width; adds casts.
* `b367f3a` — out-of-SSA copies; adds assignments.
* `12dcd5e` — `add`/`sub` now emit flag effects; adds statements.

Each measurement is ~37 minutes (56 cells, each spawning a Joern JVM for GED), so binary
search over the 8-commit range is ~3 runs. Budget for it rather than shortcut it.

#### 0.4 decision for `3ef32ae`: KEEP it. No statement-shape predicate works.

The use-count predicate was implemented and measured. It **also** breaks
`12_loop_rotation:gcc:O2:find_first_set`. Reading that function settles the question:

```c
// source:  for (int i = 0; i < 32; i++) if ((x >> i) & 1u) return i;
// gcc -O2: xor %eax,%eax ; jmp L ; L2: add $1,%eax ; cmp $0x20,%eax ; je ... ; L: bt %eax,%edi ; jae L2

cf = (((unsigned long)((unsigned int)(arg0)) >> (0 & 31)) & 1);   // <- i folded to 0
while ((~cf)) { ret = (var0 + 1); var0 = ret; ... }
```

The `bt %eax,%edi` was hoisted, and at the hoist position `var0 = 0` dominates, so
**constant folding baked the shift amount to 0**. The loop tests bit 0 forever.

Note what that is and is not:

* it is NOT "the body reads a preamble destination" — the body never reads `cf`, so
  the use-count rule permits the hoist;
* it IS "the preamble reads a register the body writes" — the old rule's condition.

So the old rule is correct here, the use-count rule is correct for the `loops` family,
and **neither is correct for both**. The real hazard is *"is the hoisted expression's
meaning preserved at the new position"* — a dominance question. In the `loops` cases the
preamble's read was not constant-foldable, so it survived as a variable reference and
stayed correct; here it was foldable, so it did not. No test over statement shapes
distinguishes those two, because the difference is what a later pass will do with the
expression, not what the expression looks like.

**Decision: keep `3ef32ae`.** It is conservatively safe and costs 7 GED cells (+3
partial). Recovering them is Phase 2 work: with value identity, use lists and dominance,
"may this expression move to this point" is a query, not a guess. Do not attempt a
fourth predicate.

That is three wrong theories in this one function today — invariance, use-count, and
before them the claim that the original copy-chain rule was unsound. Each was written
with a confident doc comment. The predicate is the wrong tool, and the repeated failure
to find one is the strongest evidence in this document for Phase 2.

**Independent bug found while reading it:** `while ((~cf))` is bitwise NOT of a 0/1
flag, which is always true — the same defect logged for the flags branch, but present on
`master` today, in a function whose verdict currently passes. It passes because the loop
exits via the `ret == 32` path instead. Logged separately.

#### superseded: narrow the predicate, do not revert

The requirement is over-broad, not wrong. It declines every hoist whose preamble reads a
body-assigned register; only `find_first_set` at gcc:O2 actually needs the decline.

The hazard is not "the preamble reads something the body writes" — it is **"the hoisted
value is not folded into the condition."** When the preamble's destination has exactly
one use, and that use is the condition, copy propagation inlines it and the condition is
re-evaluated per iteration, so hoisting is safe. When it has other uses the copy
survives as a separate statement and goes stale. That is a **use-count** question, not an
invariance question.

Proposed predicate: hoist iff every preamble destination has exactly one use, and that
use is in the condition. Verify it distinguishes `find_first_set` (must decline) from
`sum_to` / `factorial` / `matmul`'s headers (may hoist). If it does, the 7 `loops` cells
recover with `find_first_set` still passing.

This is a predicate *replacement*, not another special case — but it is still a
statement-shape test standing in for a dataflow fact, which is why Phase 2 subsumes it:
with `ValueId` and real use lists, "does this value have one use, in the condition" is a
lookup rather than an AST walk.

### Phase 1 — one pipeline, contracts enforced

No output change. From `decompiler-middle-architecture.md` §5 Phase 1.

| # | task | acceptance |
|---|---|---|
| 1.1 | One `DecompilerPipeline::run_function()` behind all four entry points | all four produce byte-identical output |
| 1.2 | One pass list, one pass-dump implementation | no duplicated sequences |
| 1.3 | Structural accounting + prepared-AST verification unconditional in the gate | no env-var-gated verification |
| 1.4 | Every stage returns `(artifact, diagnostics, trust)` | a failed invariant selects a fallback, does not continue silently |

### Phase 2 — typed values: `ValueId` + `MachineSort`

The keystone. Everything in §1.1 that is a *value* bug is fixed here, and this is the
phase that lets later fixes be GED-neutral.

| # | task | acceptance |
|---|---|---|
| 2.1 | `ValueId` (opaque) + `ValueInfo { sort, storage, definition }`; `Storage = RegisterView \| StackObject \| AbiInput \| FrameBase \| Temporary` | no `reg#version` string anywhere |
| 2.2 | Exact width on every constant, value, op, comparison and load result | the raw/canonical dual LLIR path is deleted |
| 2.3 | Phis become real instructions; out-of-SSA is coalescing | `insert_phi_copies` deleted; **`signs` still correct AND `matrix` GED back to ≤3.0** |
| 2.4 | Passes key on `ValueId`; naming/type recovery/rendering stop parsing names | `remap_type_map` and renderer thread-local name maps deleted |
| 2.5 | ABI inputs/outputs explicit, with the function's return type | `matmul` declares no `ret`; **`countdown` recovers `int(int)`** |
| 2.6 | `FrameBase` / `StackObject` / explicit address-of | a frame base cannot be spelled as a C local; the 6 C++ quarantines lift with both verifier and differential passing |

2.3 and 2.5 are the two that should *reduce* GED. They are the test of the whole
thesis: if typed values do not recover the lost GED, the diagnosis is wrong.

### Phase 3 — typed predicates

| # | task | acceptance |
|---|---|---|
| 3.1 | `FlagEffect = Defined(expr) \| Preserved \| Undefined`, total per producer | no producer omits a flag |
| 3.2 | Lazy `FlagDef { op, lhs, rhs, result, width, prior_flags }` | flags materialise only where demanded |
| 3.3 | One consumer mapping → `BoolId`; branch consumes `BoolId` | no lifter writes `Ule`/`Slt`/`Sle` |
| 3.4 | HIR lowering takes the boolean directly; no backward search, no `Flag`-vs-`Temp` test | the `flags-architecture` polarity regressions do not reproduce |
| 3.5 | Dominance-aware verifier rejects reading an `Undefined` flag | fails closed |
| 3.6 | Provenance-based rendering: reconstruct `a <= b` | no raw `sf`/`of`/`zf` in output where a comparison exists |
| 3.7 | Tests: 16 Jcc families, SETcc, CMOVcc, ADC/SBB, widths 8/16/32/64, shift counts 0/1/>1, handwritten asm, UB-free inputs | `14_flag_effects` green, `01_conditional_polarity` unchanged |

The existing branch `flags-architecture` (`06579df`) is a **rehearsal**, not a
foundation: it satisfies 3.3 and nothing else, and its regressions are precisely what
3.4 and 3.6 exist to prevent. Do not merge it.

### Phase 4 — region ownership as a computed partition

| # | task | acceptance |
|---|---|---|
| 4.1 | Explicit terminators: cond branch on `BoolId`, direct jump, indirect jump (known/unknown), switch, return, tail call, non-returning | an unknown indirect jump is never rendered as a call |
| 4.2 | CFG completeness result `Complete \| Incomplete(reason, targets, ranges)` | discovery failure is reported, not absorbed |
| 4.3 | Regions from dom/postdom + loop forest + SESE; ownership is a partition | `visited`-order ownership deleted |
| 4.4 | Every unstructurable edge becomes an explicit label/goto | zero `BlockDropped` / `BlockDuplicated` / `EdgeUnaccounted` / `ImpliedEdgeAbsent` / `GotoTargetMissing`; `EdgeViaGoto` counted as quality debt |
| 4.5 | Shadow-mode comparison against the old structurer | replaces it only with zero semantic regressions and materially fewer goto-only edges |
| 4.6 | Resolve clang -O0 relative jump tables | `statemachine:clang:O0` case arms enter the CFG |

Acceptance for the family: `13_loop_early_exit`'s six shapes, including the `break`
and `continue` cases that currently fail.

### Phase 5 — delete the compatibility layer

`value_number` string mangling; AST flag hoisting by shape; raw/canonical type-map
reconciliation; frame-pointer verifier exceptions; duplicated pipeline bodies;
renderer thread-local semantic context. Leaving both alive lets new callers recreate
the same bug class.

## 4. Discipline

Every slice, without exception:

```bash
cargo test --lib --tests
scripts/decbench-local-gate.sh          # lane 3 MUST run
tools/roundtrip_review.py --check
git diff --check
```

A slice is not done if a local gate regresses, if an improvement is recorded without
reading the changed output, or if remote CI is red / queued / skipped / missing.

**Report both axes, always.** The specific mistake this document exists to prevent is
reporting a correctness gain without its GED cost. "92% correct" and "25 cells
regressed" are the same session.

### Stop conditions

Adopted from `decompiler-middle-architecture.md` §7. Any of these means the slice has
crossed the boundary the wrong way — redesign, do not patch:

* a semantic value is identified by parsing a display name;
* equivalent booleans take different paths because one is a `Flag` and one a `Temp`;
* exact width is recovered from register spelling;
* a raw frame/stack register is emitted as a C variable to preserve an address;
* a block is owned by whichever arm visited it first;
* an unknown indirect jump renders as a call;
* a verifier detects corruption and the function continues through optimisation anyway;
* a fix for one CFG silhouette regresses another.

I crossed the first of these in `insert_phi_copies` — it matches phi results by string
name — and shipped it. That is the concrete reason this list needs to be a gate and
not a memo.
