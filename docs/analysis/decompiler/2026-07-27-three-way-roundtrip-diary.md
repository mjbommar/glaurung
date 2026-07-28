# Three-way round-trip study: glaurung vs Ghidra vs angr

> **Status, 2026-07-28:** This is retained as a historical measurement diary.
> Its numeric comparisons were made against `b66a4cb`; loop-form and canonical
> `Expr::Select` work landed upstream afterward. The useful dispatch, flag, and
> shared-pipeline work was rebased, repaired, and integrated in `39d1b44`,
> `416b02d`, and `2f32318`. On that integrated tree the authoritative
> 56-lane/623-function execution-differential matrix had zero regressions and
> refreshed three improvements. Re-measure competitor metrics before using the
> rankings below as a current claim.

**Date:** 2026-07-27
**Method:** `C -> binary -> C`, read side by side, per function, with
`tools/roundtrip3.py`. Corpus: `tests/decbench_corpus/src` (14 programs) at
gcc/clang `-O0`, plus targeted fixture cases.
**Comparators:** Ghidra 11.4.2 (via `tools/ghidra_decompile.py`), angr 9.3.0
(via `tools/angr_decompile.py`).

This is a working diary — observations in the order they were made, with the
evidence that produced them. The synthesis is at the end.

## 0. Why read output instead of reading metrics

The three DecBench metrics each compress a function to one number and none of
them knows whether the code is correct. `structs:dist2` scores a *perfect* graph
edit distance of 0.0 while its body reads two locals nothing assigns. Meanwhile a
`for` loop recovered as `while (1) { if (!c) break; ... }` is instantly visible by
eye and costs GED silently on every loop in the corpus.

Where the three decompilers stand on the corpus, measured, 56 cells each, same
harness (lower GED better, higher type/byte better):

| | GED | type_match | byte_match |
|---|---|---|---|
| glaurung (master) | 12.678 | 0.678 | 0.197 |
| Ghidra 11.4.2 | 11.497 | 0.903 | 0.300 |
| angr 9.3.0 | **9.926** | 0.694 | 0.274 |

Two caveats that matter before reading anything into those numbers:

* **Ghidra's type lead is largely an artifact.** The corpus is built `-g`,
  DecBench's ground truth *is* that DWARF, and Ghidra's default analyzers include
  the DWARF analyzer — so it is reading the answer key. Scored through one
  identical scorer with `--strip-debug`, Ghidra falls to 0.000 on `structs` and
  0.650 on `arrays`, i.e. below us. Its *inference* is not what is ahead.
* **angr's GED lead is real** and is the interesting one: it recovers source-like
  control flow from the instruction stream alone.

---

## 1. Loop forms: we have no `do-while` and no `for` (systematic, corpus-wide)

The first function read, `loops.c:count_bits`, shows it immediately.

```c
/* source */
int count_bits(unsigned x){ int c=0; do { c += x&1; x>>=1; } while(x); return c; }
```

```c
/* ghidra */                          /* angr */
do {                                  do
  c = c + (x_local & 1);              {
  x_local = x_local >> 1;                 v1 += i & 1;
} while (x_local != 0);                   i >>= 1;
                                      } while (i);
```

```c
/* glaurung */
while (1) {
    local_4 = (local_4 + (arg0 & 1));
    arg0 = ((unsigned int)(arg0) >> 1);
    if ((arg0 == 0)) { break; }
}
```

And `loops.c:sum_to`, source `for(int i=0;i<n;i++) s+=i;`, comes back from angr as
a literal `for (i = 0; i < a0; i += 1)` and from us as another
`while (1) { if (...) break; ... }`.

**Root cause, verified in the code**: `Region` (`src/ir/structure.rs:28`) has
exactly seven variants —

```rust
Block | Seq | IfThen | IfThenElse | While | Switch | Unstructured
```

There is **no `DoWhile` and no `For`**. Ghidra's `block.hh` carries `BlockWhileDo`,
`BlockDoWhile`, `BlockIf`, `BlockSwitch`, `BlockGoto`, `BlockMultiGoto`, and angr
emits all three loop forms. So every `do`/`for` in the corpus is lowered through
the one loop shape we can express, paying an extra condition node and an extra
break node each time.

This is a *representational* gap, not a heuristic one: no amount of tuning
`detect_if_shape` can emit a construct the region tree cannot name. It is also
plausibly a large share of our GED distance from angr, because loops are the most
common structure in the corpus.

*(Continued below as evidence arrives.)*

---

## 2. Per-program standings, and what they say

GED at `-O0` (mean of gcc and clang lanes), measured, lower is better:

| program | glaurung | ghidra | angr | best |
|---|---|---|---|---|
| arith | 1.00 | **0.00** | **0.00** | both |
| arrays | 5.67 | **1.00** | **1.00** | both |
| branches | 7.00 | 7.50 | **5.50** | angr |
| checksum | 4.00 | **0.00** | **0.00** | both |
| fixedpoint | 1.33 | **0.00** | **0.00** | both |
| linkedlist | 4.75 | 2.50 | **0.00** | angr |
| loops | 3.33 | **0.00** | **0.00** | both |
| matrix | 13.00 | **3.00** | **3.00** | both |
| recursion | 6.00 | 6.00 | **2.50** | angr |
| sort | 8.25 | 4.00 | **1.50** | angr |
| statemachine | 31.00 | 38.00 | **15.00** | angr |
| strops | 5.50 | 2.50 | **2.00** | angr |
| structs | **0.00** | **0.00** | **0.00** | tie |
| **switch_jt** | **23.00** | 42.00 | 45.00 | **GLAURUNG** |

### 2a. What we do well

**Switch and jump-table recovery is our strongest area, by a wide margin.**
`switch_jt` is 23.00 against Ghidra's 42.00 and angr's 45.00 — we are roughly
twice as good as either. `ir::switch_ladder` recognising a gcc `-O0` comparison
decision tree as the `switch` it is, rather than as nested if/else with gotos, is
a genuine differentiator neither competitor matches. (This measurement is of
*master*, before this session's dispatch work, which improves it further to 18.0.)

Also worth stating plainly: we produce parseable C for 99.7 % of a 1646-function
corpus sweep with zero panics, and the execution differential — recompile our C
and run it against the original — is a stronger correctness check than either
competitor ships. Neither Ghidra nor angr can tell you whether their output
*behaves* like the binary; we can, and that is how the `fletcher16` and `signs`
defects were found.

### 2b. What we do poorly — and the shape of it

Look at the four programs where **both** competitors score a perfect 0.00 and we
do not: `arith` (1.00), `checksum` (4.00), `fixedpoint` (1.33), `loops` (3.33).
These are the *simplest* programs in the corpus. A gap that appears on the easy
cases is not an exotic-shape problem; it is a **systematic per-construct tax**.

Section 1 identifies most of it: we cannot express `do-while` or `for`, so every loop
is inflated into `while (1) { if (!cond) break; ... }`.

**But `arith` contains no loop at all** — `grep -cE '\b(for|while|do)\b'` returns 0 —
so loop form cannot explain its 1.00. Checking each program rather than generalising
from `loops`:

| program | loop keywords | our GED | cause |
|---|---|---|---|
| `loops` | 3 | 3.33 | loop form |
| `checksum` | 2 | 4.00 | loop form |
| `fixedpoint` | 1 | 1.33 | loop form |
| `structs` | 0 | 0.00 | none — we tie |
| `arith` | **0** | 1.00 | **ternary rendering (§8.6)** |
| `branches` | **0** | 7.00 | **ternary rendering (§8.6)** |

Every loop-containing program scores >0 for us and 0.00 for both competitors, and the
one no-loop program with no other defect ties at 0.00. The correlation is clean. The
generalisation to `arith` was not, and I made it before checking — the same
extrapolation-from-one-case failure this repository's own value-model doc records
three instances of.

`matrix` (13.00 vs 3.00) is the same tax multiplied — three nested loops, each
paying the inflation, which is exactly what the value-model doc recorded when it
bisected `3ef32ae`.

### 2c. Quantified: we emit the degenerate loop form 19 times out of 19

Counting the loop construct each decompiler emitted, over every corpus function
whose *source* contains a loop (gcc and clang `-O0`):

| | `for` | `do-while` | `while (cond)` | `while (1) { if(..) break; }` |
|---|---|---|---|---|
| **glaurung** | 0 | 0 | 0 | **19** |
| ghidra | 15 | 1 | 1 | 2 |
| angr | 18 | 1 | 0 | 0 |

**Every loop in the corpus, without exception.** This is the single largest and
cheapest-to-explain difference between us and both competitors, it lands on the
most common construct in any program, and it is invisible in a mean because it is
uniform.

Two distinct causes, and both must be fixed:

1. **Representational** — `Region` cannot name `DoWhile` or `For`, so those two
   forms are unreachable no matter what the structurer decides.
2. **`3ef32ae`** — the loop-header hoist turned even the plain `while (cond)` case
   into `while (1) { if (!cond) break; ... }`. The value-model doc bisected this
   and chose to keep it on soundness grounds; the measurement above is the price,
   paid on every loop. Note the doc's own follow-up found the soundness claim was
   false as stated ("a soundness argument that is only tested at the predicate
   level is not tested"), so this is worth re-opening with a fixture that
   actually misbehaves rather than a predicate argument.

### 2d. Where our expressions are already competitive

Worth recording because it narrows where work should go. On `arrays:sum_array` the
loop body is:

```c
ghidra:    s = s + a[i];
glaurung:  local_8 = (local_8 + arg0[(long)((int)(local_4))]);
angr:      v0 += *((int *)(a0 + i * 4));
```

We recover **`a[i]` array indexing**, which angr does not — it emits raw pointer
arithmetic. Ghidra gets there via DWARF. Our remaining defect on that line is cast
noise (`(long)((int)(...))`), not the idiom.

Similarly `arith:addmul` comes out as a clean one-line `return` from us, while
Ghidra emits three dead DWARF-derived locals (`a_local`, `b_local`, `c_local`).

**The conclusion this points to:** our expression and idiom recovery is
competitive; essentially all of our GED distance is in **control-flow shape**. That
is consistent with the two places we win (`switch_jt`, where control-flow
recognition is our specialty) and with 49 % of fixture failures sitting in
structuring.

---

## 3. angr synthesizes aggregate types with no debug info

`linkedlist:list_sum`, source `while(h){ s+=h->val; h=h->next; }`:

```c
/* angr — note this is INFERRED, the binary's DWARF was not consulted */
typedef struct struct_0 {
    struct struct_0 *field_0;
    unsigned int field_8;
} struct_0;

unsigned int list_sum(struct_0 *a0) {
    struct_0 *i;
    for (v1 = 0; i; i = i->field_0) { v1 += i->field_8; }
}
```

```c
/* glaurung */
local_4 = (local_4 + *(int *)((local_18 + 0x8)));
local_18 = *(long *)(local_18);
```

```c
/* ghidra — via the DWARF analyzer, i.e. reading the answer key */
for (h_local = h; h_local != (node *)0x0; h_local = h_local->next) {
    s = s + h_local->val;
}
```

angr recovered a **recursive struct** from access offsets alone: offset 0 is a
pointer to the same shape, offset 8 is a 4-byte integer. It then renders field
accesses as `->field_0` / `->field_8` and even hoists the initialiser into the
`for`.

This is the mechanism behind our `structs` (0.25) and `linkedlist` (0.50)
`type_match` scores, and it is the *right* comparison to make: Ghidra's aggregate
recovery here is DWARF, but **angr's is inference**, so it is a capability we could
actually match. It is also the answer to "what is the ceiling without DWARF" — the
earlier estimate put our inference ceiling at 0.917 (gcc:O0) assuming aggregates
stay unrecoverable. angr shows aggregates are *not* inherently unrecoverable.

---

## 4. clang -O0 rotated loops: we are correct, angr is clean, Ghidra breaks

`loops:factorial` at clang -O0 (`while(n>1){ f*=n; n--; }`):

```c
/* angr */                          /* ghidra */
for (v0 = 1; i > 1; i -= 1)         /* WARNING: Variable defined which should
{                                      be unmapped: n_local */
    v0 *= i;                        for (f._4_4_ = n; 1 < f._4_4_;
}                                        f._4_4_ = f._4_4_ + -1) {
                                      local_18 = f._4_4_ * local_18;
                                    }
```

```c
/* glaurung */
while (1) {
    if ((local_4 <= 1)) { break; }
    local_10 = ((long)((int)(local_4)) * local_10);
    local_4 = (local_4 - 1);
}
```

Ghidra's DWARF dependence **backfires** here: it maps `f` onto a stack slot the
clang codegen reuses and emits `f._4_4_`, a sub-field artifact, plus a warning.
Ours is semantically correct and merely mis-formed. This is a useful corrective to
the "Ghidra is simply ahead" reading — on the lane where it must reconcile DWARF
against optimised-ish codegen, it degrades in a way we do not.

It also sharpens where angr's clang:O0 advantage (GED 3.19 against our 6.23) comes
from: not from better semantics, but from emitting the loop in its source form.

---

## 5. `statemachine:fsm` — the one where we are worst, and why

Ours is GED 31, Ghidra 38, angr **15**. angr's recovery:

```c
for (i = 0; i < a1; i += 1) {
    v0 = a0[i];
    if (v1 == 3) return 1;
    if (v1 <= 3) {
        if (v1 == 2)      v1 = (v0 == 99 ? 3 : 0);
        else if (v1 <= 2) {
            if (!v1)      v1 = v0 == 97;
            else if (v1 == 1) v1 = (v0 == 98 ? 2 : v0 == 97);
        }
    }
}
return v1 == 3;
```

Two things it does that we do not:

* **It declines to emit a `switch`** and instead produces a comparison ladder that
  matches the source CFG more closely. GED does not reward the `switch` keyword; it
  rewards graph shape. Our instinct to always recover a `switch` is not always the
  GED-optimal — or the readable — choice.
* **Ternary and boolean-assignment recovery**: `v1 = (v0 == 99 ? 3 : 0)` and
  `v1 = v0 == 97` collapse a diamond into one statement, removing two nodes each.
  We emit the full if/else diamond.


---

## 6. The measurement that explains the GED gap

An angr source study predicted our O0 gap is **statement count, not structure**. Testing
that over 60 captured functions confirms the headline and refutes the proposed
mechanism, which is worth recording separately.

### Statements per function (all statements)

| | mean stmts/fn | ratio vs source |
|---|---|---|
| source | 2.00 | 1.0x |
| **angr** | 6.86 | 4.3x |
| ghidra | 15.64 | 10.0x |
| **glaurung** | **30.79** | **16.6x** |

We emit **4.5x more statements than angr**. The predicted mechanism — assignments
whose RHS is a bare temporary, removable by single-use folding — accounts for only
**9 %** of our assignments. So expression folding is *not* our main problem, which is
a useful negative result: it would have been the obvious thing to build.

### Control-flow statements, which is what GED actually counts

| | cf/fn | `for` | `do` | `while` | `break` | `goto` | `if` | `return` |
|---|---|---|---|---|---|---|---|---|
| **glaurung** | **5.2** | **0** | **0** | 41 (all `while(1)`) | **62** | **36** | 86 | 61 |
| ghidra | 3.1 | 30 | 2 | 9 | 8 | 0 | 53 | 74 |
| angr | 2.9 | 34 | 2 | 6 | 5 | 4 | 32 | 81 |

**We emit 1.8x the control-flow statements of angr**, and the excess decomposes
cleanly into three named causes:

| artifact | excess vs angr | cause |
|---|---|---|
| 57 extra `break` | `while(1){if(!c) break;}` | no `For`/`DoWhile` region; plus `3ef32ae` |
| 36 extra `goto` | vs angr's 4, Ghidra's **0** | `Region::Unstructured` has no goto-virtualization fallback |
| 54 extra `if` | 86 vs 32 | the loop guards above, plus no ternary / short-circuit recovery |

That is **~48 % of our control-flow statements being artifacts**, and it accounts for
the GED gap without needing any other explanation.

### Declarations

glaurung 3.7/fn, ghidra 3.5/fn, **angr 0.1/fn**. angr declares almost nothing because
it folds aggressively into use sites. Declarations are not CFG nodes so this barely
touches GED — but it is most of why angr's output *reads* better, and it is the
`_fold_oneuse_expressions` pass.

---

## 7. Why we win `switch_jt`, with the mechanism

gcc `-O0` lowers `switch(op){case 0..7}` into a comparison **decision tree** (a
binary search over the value), not a jump table. The three recoveries:

* **glaurung** — a complete 8-case `switch` with `default`. GED **23**.
* **Ghidra** — the full nested if-tree, eight levels deep. GED 42.
* **angr** — `switch` containing only `case 7`, with the remaining seven cases left
  as an if-tree inside `default`. GED 45.

`ir::switch_ladder` recognising the ladder is a real differentiator, and angr's
source says why it does not match us: `LoweredSwitchSimplifier` encodes GCC's own
`default_case_values_threshold` as a **refusal** rule —
`max_continuous_cases >= 6` means "GCC would have used a jump table, so this
if-tree is probably not a lowered switch". Our eight continuous cases trip exactly
that rule, so angr declines the transform by design.

We are more aggressive here and, on this evidence, right to be. Two lessons, in
both directions:

* **Keep this.** It is the only place we beat both competitors, and it beats them
  by ~2x.
* **But borrow their guard rails.** angr pairs its aggression with four documented
  accept/reject rules transcribed from compiler source. We have the aggression and
  not the rules; a false positive turns a genuine if-tree into a wrong `switch`.
  Worth adopting the *idea* of citing the compiler's own threshold, even where we
  choose a different threshold.

Remaining defects visible in our own output on this function: cast noise
(`(unsigned long)((unsigned int)(arg1))` on every operand) and scrambled case order
(7,6,5,4,3,2,0,1 rather than 0..7). Neither is structural; both are cheap.

---

## 8. Synthesis

### 8.1 What we do well

1. **Lowered-switch recovery.** `switch_jt` GED 23 against Ghidra 42 and angr 45 —
   the only place we beat both, and by ~2x. `ir::switch_ladder` recovers a gcc `-O0`
   comparison decision tree as the `switch` it is; angr explicitly declines this
   case and Ghidra does not attempt it.
2. **Jump-table dispatch** (post this session's work): `dense_jumptable` at clang -O0
   is recovered as a complete 8-case switch where Ghidra reports
   *"Could not recover jumptable ... Too many branches"* and falls back to
   `Treating indirect jump as call` on `fsm`.
3. **Array indexing.** We emit `a[i]`; angr emits `*((int *)(a0 + i * 4))`. Ghidra
   matches us only via DWARF.
4. **Expression-level output is competitive.** `arith:addmul` is a clean one-line
   `return` from us while Ghidra emits three dead DWARF locals.
5. **The execution differential.** Neither competitor can tell you whether its output
   *behaves* like the binary. Ours can, and that is how `fletcher16`, `signs` and the
   `sub`-flags defect were found. This is a real asset and worth protecting.
6. **Robustness.** 1646 functions swept, 99.7 % gcc-parseable, zero panics.

### 8.2 What we do poorly, ranked by measured cost

1. **Loop form — 19 of 19 loops wrong.** No `For`, no `DoWhile` in `Region`. Costs 57
   excess `break`s and ~40 excess `if`s corpus-wide. **The single largest measurable
   defect.**
2. **No total structuring.** 36 `goto`s against Ghidra's 0 and angr's 4.
   `Region::Unstructured` is a dead end where both competitors virtualize one edge and
   retry.
3. **No aggregate type inference.** angr synthesizes recursive structs from access
   offsets with no debug info; we emit `*(int *)(p + 8)`. This is our `structs` 0.25 /
   `linkedlist` 0.50 `type_match`.
4. **No ternary / short-circuit recovery.** `v1 = (v0 == 99 ? 3 : 0)` from angr versus
   our full 4-node diamond.
5. **Flag leakage into output.** 27 flag assignments survive into rendered C
   (`cf = ...`, `ule = ...`). Neither competitor emits any.
6. **Cast noise.** `(unsigned long)((unsigned int)(arg1))` on nearly every operand.
7. **Weak expression folding.** `copy_prop` handles only copies, so `t = a + b;
   x = t;` never collapses. Worth noting this is *not* our dominant problem (bare-temp
   assignments are 9 % of ours) — a useful negative result, since it is the obvious
   thing to build and would have been mostly wasted.

### 8.3 What to take from Ghidra and angr

From the angr source study (`fast` preset is what beat us — three of the four
headline SAILR de-optimizations were **off**, so the win is the *pipeline*, not the
exotic passes):

* **Goto virtualization as the structuring fallback.** When no schema matches, pick
  one edge by heuristic, convert it to a `goto`, remove it, retry. Termination is
  structural (each step removes an edge). This is what makes their structurer total
  and ours partial.
* **Restructure-and-count validation.** Every speculative rewrite re-runs the
  structurer and compares an explicit quality metric (goto count, label count, loop
  kind ranked `for > while > do-while`), rolling back automatically. This is what
  makes aggressive heuristics safe to write — and it is exactly the discipline this
  repository has been missing.
* **`for`-loop promotion**: if every continue-prelude ends with the same statement it
  becomes the iterator; pull the predecessor's last assignment in as the initializer.
* **Deferred flag records instead of a flag enum**: the arithmetic writes
  `(op, dep1, dep2)`; the branch resolves `(condition_code, op)` through a table into
  a real comparison with correct widths. Removes the whole "which `cmp` wrote this
  flag" bug class — of which we have now found four instances.
* **Jump-table reject list** — shape check, mapped-section check, all-entries-readable,
  decode-check the target, and reject counts of exactly 1 / 0x100 / 0x10000 (the
  signature of a failed constraint). Cheap, and it is what stops one bad table from
  destroying a function.

From reading Ghidra's *output* rather than its source: its DWARF dependence is a
double-edged asset — it wins `type_match` by reading the answer key, and it produces
`f._4_4_` garbage plus warnings at clang -O0 when DWARF disagrees with codegen. Our
DWARF-free inference degrades more gracefully.

---

## 8.4 Confirmation on the dedicated loop fixtures

Repeating the loop-form count on `tests/decompiler_fixtures/src/{03_loop_shapes,
12_loop_rotation,13_loop_early_exit}.c` at gcc and clang `-O0` — 66 functions
written specifically to exercise loop shapes:

| | `for` | `do-while` | `while(cond)` | `while(1)+break` | no loop | `goto` |
|---|---|---|---|---|---|---|
| **glaurung** | **0** | **0** | **0** | **60** | 6 | **31** |
| ghidra | 37 | 8 | 2 | 17 | 2 | **0** |
| angr | 51 | 6 | 2 | 5 | 2 | **0** |

Across both corpora that is **126 functions** examined and **zero** instances of us
emitting `for`, `do-while`, or even a plain `while (cond)`. And 31 gotos on the loop
fixtures against **zero** from either competitor.

The two findings are now as well-evidenced as anything in this repository:

1. we have exactly one loop form and it is the wrong one in every case measured;
2. we are the only one of the three that ever falls back to `goto`.

---

## 8.5 Both competitors independently converged on the same three answers

Source studies of Ghidra's C++ decompiler and angr's Python one were done separately,
against different questions. They agree on three mechanisms, which is much stronger
evidence than either alone.

### (a) Structuring is made TOTAL by forcing a goto — not by having more patterns

* **Ghidra** — `CollapseStructure::collapseAll` (`blockaction.cc:1877-1893`):
  ```cpp
  isolated_count = collapseInternal(0);
  while (isolated_count < graph.getSize()) {
      FlowBlock *targetbl = selectGoto();     // marks one edge unstructured
      isolated_count = collapseInternal(targetbl);
  }
  ```
  `selectGoto` (`:1260-1277`) calls `startbl->setGotoBranch(outedge)`, which guarantees
  `ruleBlockGoto` fires next pass.
* **angr** — `phoenix.py:188-238`, and when nothing matches,
  `_last_resort_refinement` (`:3021-3141`) virtualizes one edge into a `goto`.
  Termination is structural: each step removes an edge.

**The decisive detail: Ghidra has only ELEVEN collapse rules**
(`blockaction.hh:209-219`) — fewer than one might guess, and comparable to our three
detectors. The difference is not the pattern catalogue. It is that neither system can
get stuck, because when nothing matches they *make* something match.

Our `build()` (`structure.rs:527`) has no such step; unmatched blocks fall into
`Region::Unstructured` and stay there. That is the mechanism behind 49 % of failures,
and it is a ~50-line control-flow change to the driver, not a research problem.

### (b) Edge semantics belong ON THE EDGES, computed once

Ghidra stores `f_goto_edge | f_loop_edge | f_back_edge | f_irreducible |
f_loop_exit_edge` on each edge (`block.hh:108-118`) from a single Tarjan pass
(`structureLoops`, `block.cc:2194-2215`), and every rule consults three derived
predicates (`block.hh:336-345`) rather than re-deriving. Irreducible CFGs are not a
special case — they are edges with a flag that every rule refuses, which makes them
goto candidates automatically.

We use `visited: HashSet<usize>` for this, and it is doing double duty as "already
emitted" and "do not re-enter" — which is exactly where the sibling-arm and
double-emission defects `structure_accounting.rs` reports come from.

### (c) A condition code is not a special kind of value

Ghidra models x86 flags as ordinary **1-byte registers** holding boolean expressions
(`ia.sinc:38-41`, `:2142-2167`), and a single `cc` subtable exports the branch
condition (`:1523-1538`). Comparisons are then reassembled by ordinary term rewriting
— `RuleSborrow` (`ruleaction.cc:3338`), `RuleLessEqual` (`:2223`), `RuleCarryElim`
(`:3912`), `RuleBoolNegate` (`:5446`).

The confirming measurement, run over all ~150 decompiler sources:

```
$ grep -rn '"ZF"\|"CF"\|"SF"\|"OF"\|zeroflag\|carryflag' $GHIDRA/decompile/cpp/*.cc *.hh
(no output)
```

**There is no flag-register name anywhere in Ghidra's mid-end.** angr reaches the same
place differently: it defers `(op, dep1, dep2)` and resolves `(condition_code, op)`
through a table after propagation (`ccall_rewriters/amd64_ccalls.py`).

Our `Flag { Z, C, Ule, S, Slt, Sle, O, P, A, Bit }` mixes real status bits with
*derived predicates*. The `Ule`/`Slt`/`Sle` variants exist precisely because our lifter
must pre-fold multi-flag conditions itself — we moved `RuleSborrow`'s job into the
lifter, once per instruction pattern, per architecture. And `ssa.rs:18` does not
version flags, so `dce.rs:21` records the consequence in its own words: *"a read of
`zf` anywhere keeps every `zf` write alive. Flags have no value identity."*

### (d) One more, from Ghidra only: structure a COPY

`ActionBlockStructure` structures `graph.buildCopy(data.getBasicBlocks())`
(`blockaction.cc:2177`) — a throwaway mirror. Rules may therefore freely delete edges
and move nodes, and `identifyInternal` (`block.cc:940-963`) *moves* blocks into the new
parent rather than referencing them. Block conservation is structural.

Our `structure_accounting.rs` is 921 lines of auditing for a property that would be
free under this design. That is worth stating plainly: the verifier is excellent, and
it is compensating for an architectural choice.

---

## 8.6 The second control-flow defect: no ternary recovery, and it costs 8.00 GED

`arith` (1.00) and `branches` (7.00) contain **no loops**, so their gap is something
else. It is the same thing in both: we never emit a conditional expression.

`arith:signs`, source `(a < 0 ? -a : a) + (b > a ? b - a : a - b)`:

```c
/* ghidra — one-armed if, 2 nodes */    /* glaurung — two-armed, 3 nodes */
iVar1 = -a;                             var2 = t0;
if (0 < a) { iVar1 = a; }               if (t0 < 0) { var3 = var0; }
                                        else        { var3 = var2; }
```

We already lift `cmovcc` to `Op::Ite` — a three-input select — and then render it as a
two-armed `if`. The readiness doc made that change deliberately and *recorded* the
rendering consequence. It is a pure rendering choice and it costs the whole `arith` gap.

`branches:classify`, source `if(a>b) return a-b; else if(a<b) return b-a; return 0;`:

```c
/* angr — one statement */
return (a0 <= a1 ? (a0 < a1 ? a1 - a0 : 0) : a0 - a1);
/* glaurung — nested if/else through a `ret` temporary, seven statements */
```

So ternary recovery is worth **8.00 GED across two programs**, comparable to loop form
on the small programs, and I had originally ranked it fourth. It is now Phase A4 in the
plan, split into A4a (render `Op::Ite` as a ternary — pure rendering, could land today)
and A4b (collapse same-destination if/else diamonds — needs a structural match).

---

## 9. Where the plan went

`docs/design/decompiler-plan-2026-07-27.md`.

It supersedes the phase ordering in `value-model-root-cause-and-plan.md`. That
document made the value model the keystone and put region ownership last; two
independent measurements say the reverse — control-flow artifacts are ~48 % of our
emitted control-flow statements, while the value-model symptom it predicted
(bare-temp assignments removable by folding) is 9 % of our assignments.

## 10. Reproducing this

```bash
# three-way capture (needs GHIDRA_INSTALL_DIR, GHIDRA_PYTHON, ANGR_PYTHON)
tools/roundtrip3.py --out /tmp/rt3 --lanes gcc:O0 clang:O0

# single decompiler, one function
tools/ghidra_decompile.py $GHIDRA_INSTALL_DIR bin.so funcname
tools/angr_decompile.py bin.so funcname
tools/dectest.py 04_switch_shapes:clang:O0:dense_jumptable --show

# the metric matrices
tools/decbench_matrix.py --json --backend glaurung|ghidra|angr
tools/decbench_compare.py glaurung=g.json ghidra=gh.json angr=a.json
```

## 11. Method notes, including one mistake worth keeping

The statement-count analysis started from a *prediction* made by a source study —
that our O0 gap would be statement count dominated by bare-temp assignments. The
headline was right (4.5x angr) and the mechanism was wrong (9 %, not dominant).
Testing it took ten minutes and changed the plan: general expression folding moved
from "obvious first move" to "explicitly do not do first".

That is the argument for the whole exercise. A plausible mechanism from a careful
reading of a competitor's source was still wrong, and only counting caught it.
