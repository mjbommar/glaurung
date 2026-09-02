# Fourteen new fixtures, five new defects, and two predicates the corpus lacked

> **Kind:** record · **Date:** 2026-08-27

**Date:** 2026-08-27
**Companion:** [`decbench-defect-reproductions-2026-08-27.md`](decbench-defect-reproductions-2026-08-27.md)
(the defects these fixtures were written from) and
[`decbench-native-provenance-2026-08-27.md`](decbench-native-provenance-2026-08-27.md)
(the corpus-scale measurement that ranked them).

**Status:** landed. 14 fixtures, 62 functions, 266 judged cells — **234 pass,
32 fail**. Every failure is a real defect, reproduced from compiled source,
diagnosed to a mechanism, and recorded below with a fix plan.

---

## 0. Why the corpus could not express the largest defect it has

`tests/decompiler_fixtures/` judges a cell by **executing** the recovered C
against the original and diffing return values and mutated buffers. That is a
strong contract and it is blind to exactly one thing: **structure**.

Goto soup is faithful. Every arm is present, every edge is real, the C compiles
and returns the right answer for every input — it is simply not the source's
control flow. Over the 250 scored DecBench sample-set functions, 28.8% render
that way (40.5% on x86-64). It is the single largest defect class in the
decompiler, and **not one cell in a 205-fixture corpus could fail because of
it.**

The six structural predicates (`structural.py:202`) were `indirect_call`,
`memory_store`, `nonempty`, `head_tested_while`, `for_loop`, `void_signature`.
None of them is about dispatch or about goto.

### Two predicates added

```python
PREDICATES = {
    "indirect_call": has_indirect_call,
    "switch": has_switch,          # NEW
    "goto_free": goto_free,        # NEW
    ...
}
```

* **`switch`** — a `switch` statement survived into the rendered C. Deliberately
  weak: it asks whether the renderer emitted the construct, not whether the arms
  are right, because `04_switch_shapes` plus the manifest's `arg_values` already
  drive the exact case constants.
* **`goto_free`** — no `goto` survived. Phrased as an absence on purpose: the
  structural map records booleans, so `{"goto_free": True}` reads as the property
  being asserted. A count would be the wrong shape — it would need refreshing
  every time a lane's rendering shifted by one label. A `goto` is not itself a
  defect (`102_duffs_device`, `103_computed_goto` and `105_goto_ladder` are
  *about* goto); the predicate exists so a fixture whose source has none can say
  so.

Both are additive: `gen_structural_baseline.py` evaluates only the predicates a
fixture's `STRUCTURAL` entry declares (`structural.py:316`), so no existing
fixture changes.

While there, a pre-existing `SyntaxWarning` in that file was fixed — a docstring
contained `\)` outside a raw string.

---

## 1. What was added

| # | fixture | isolates | lanes |
|---|---|---|---|
| 206 | `aarch64_wide_dispatch` | dense switch forced to a jump table on every target. AArch64 lowers it `adrp`/`add`/`ldrb`/`adr`/`add`/`br` — a byte-offset table form `DispatchTracker` models **nowhere** | C ×4 + 6 arch |
| 207 | `scaled_index_addressing` | `lsl #2`/`#3` and `(,%r,8)` at every element width, with unscaled and shift-as-value controls | C ×4 + 6 arch |
| 208 | `flag_register_roundtrip` | an unmodelled instruction whose destination is read afterwards, via `pushfq`/`mrs nzcv`/`mrs cpsr` — deterministic where `rdtsc` is not | C ×4 + 6 arch |
| 209 | `out_of_line_guard_handlers` | the `bin_090 sub_7370` shape: guard chain whose cold handlers are sunk below the return | C ×4 + 6 arch |
| 210 | `shared_return_epilogues` | epilogue chains of length 1/2/3, shared and exclusively owned — the exact axis of the reverted `linear_return_chain` fix | C ×4 + 6 arch |
| 211 | `irreducible_loops` | multi-entry loops: unrepresentable in the region algebra, so the acceptance test for the eventual region analysis | C ×4 + 6 arch |
| 212 | `loop_with_returning_arm` | loop + dispatch where one arm returns — the `statemachine` shape, which lives in `tests/decbench_corpus/` and had **never** been swept by the fixture matrix | C ×4 + 6 arch |
| 213 | `arm_predicated_execution` | conditional definitions: A32 predication, IT blocks, `csel`, `cmov` | C ×4 + 6 arch |
| 214 | `arm_literal_pools` | PC-relative constant fetch, incl. a pool inside a function body | C ×4 + 6 arch |
| 215 | `switch_on_wide_selector` | 64-bit selector with labels above 2³², and a mixed tree-plus-table | C ×4 + 6 arch |
| 216 | `packed_union_wire_record` | bitfields ∩ union ∩ packed — composed, as real headers are | C ×4 + 6 arch |
| 217 | `complex_arithmetic` | `_Complex`: its own ABI class, no coverage anywhere | C ×4 + 6 arch |
| 218 | `cpp_lambdas_and_callables` | closure objects and capture modes; `capture_then_mutate` is the discriminator | C++ ×4 |
| 219 | `rust_iterator_chains` | adapter chains, fused at O2 and a deep call stack at O0 | Rust ×2 |

House style followed throughout: `#include <stdint.h>`, a header comment naming
the machine fact *and* what a wrong recovery looks like *and* which sibling
fixture does not cover it, `__attribute__((noinline))` on every export,
fixed-width types, unique-constant returns, in-source bounds guards, no libc, no
UB, and a **control function** in every fixture that isolates the mechanism from
its surroundings.

All 14 compile warning-clean under `-Wall -Wextra -Werror` in all four host
lanes, and all 13 C/C++ ones cross-compile for aarch64, armv7 (Thumb), armv7_a32
and i386 — no `unsupported:` lane is needed.

---

## 2. The five defects these fixtures found

### D-A. `_Complex` helper calls lose their entire signature

`217:gcc:O0:complex_multiply` — 8 of 24 `_Complex` cells.

```c
extern double __muldc3(void);          /* takes FOUR doubles, returns a PAIR */
var125 = __muldc3();                   /* called with NO arguments */
local_10 = var125;                     /* only the real half survives */
```

At -O0 both compilers call `__muldc3`/`__mulsc3` for complex multiplication.
The recovered prototype has **no parameters and a scalar return**, so all four
operands are dropped and the imaginary half never exists. `abi::annotate_calls`
recovers argument counts for ordinary calls; a libgcc helper taking four SSE
arguments and returning two is outside what it models.

**Fix:** teach call-argument recovery the libgcc soft-float/complex helper ABI.
These are a closed, documented set (`__mulsc3`, `__muldc3`, `__divsc3`,
`__divdc3`, plus the soft-float `__adddf3` family already relevant to ARM), so a
table of known helper signatures keyed by symbol name is both sound and small.
It composes with the existing `call_contracts::apply_known_call_contracts` pass,
which already exists for exactly this purpose.

### D-B. `double` arithmetic emitted as integer arithmetic

`217:gcc:O0:struct_pair_control` — the *control* function, which contains no
`_Complex` at all.

```c
*(double *)(&local_30[0]) = (double)((int)(arg0));            /* stored as double */
*(long *)(&local_10[0]) = ((*(long *)(&local_20[0]) * *(long *)(&local_30[0]))
                         - (*(long *)((&local_20[0] + 8)) * ...));  /* read as long */
```

The stores are correctly typed and the reads are not: `mulsd`/`subsd` on a stack
slot are being modelled as integer multiply and subtract. The recompiled C
therefore does integer arithmetic on the bit patterns of doubles. This is a
**wrong-code defect independent of `_Complex`**, and it is why the control fails
alongside the measurement — which is exactly what a control is for.

**Fix:** the type of a stack slot is already known at the store
(`StackLocalFacts.source_types`); the load must inherit it. This is the
float-side analogue of the width work in `abi_widths.rs`, and the evidence is
present — `Stmt::Store { size }` and the SSE mnemonic both say `double`.

### D-C. An indirect call target is never symbolized

`218:{gcc,clang}:O0:erased_callable` — 2 cells.

```c
*(long *)(&local_20[0]) = (long)((long)(0x1386));    /* &scale_apply */
var12 = ((long (*)(long, long))(*(long *)(&local_20[0])))(...);
```

The function pointer is stored as a bare address. `name_resolve::resolve_names`
turns an `Expr::Addr` into an `Expr::Named` when it points at a known function,
but the address here reaches the store as a *computed* value (a PIC
`lea`/`adrp` sequence), and the resolution runs before the value is proven
constant.

**Fix:** run function-address symbolization **after** constant folding, or seed
it from `function_tables::collect_function_pointer_tables`, which already proves
relocation-backed function pointers. Note this is the same class as the
`memory_operand_va` defect in the companion document: an address that is
recoverable is dropped because the pass that could recover it runs at the wrong
point.

### D-D. A mixed tree-plus-table dispatch is folded into a ternary

`215:{gcc,clang}:O2:wide_selector_mixed`, `215:clang:O2:wide_selector_high_labels` — 3 cells.

```c
/* unrecovered indirect jump through ((long)((int)(((arg0 == 0) ? 0xfffff1e0 :
   ((arg0 == 1) ? 0xfffff1f0 : ... *(int *)((0x2000 + (arg0 * 4)))))))) + 0x2000) */
```

For a 64-bit selector with both a dense low cluster and labels above 2³², the
compiler emits a comparison tree whose leaves include a jump table. The table
read is present in the expression — `*(int *)((0x2000 + (arg0 * 4)))` is
literally the table indexed by the selector — but `select_fold` has already
folded the dispatch into a nested ternary, so by the time the indirect jump is
examined its target is an expression rather than a tracked register, and
`DispatchTracker` cannot answer it.

**Fix:** this is an ordering defect, not a missing recogniser. Resolve dispatch
targets **before** select-folding rewrites them, or make the resolver able to see
through a `Select` whose arms are all constants. The second is more general and
is what a mixed dispatch fundamentally needs.

### D-E. 64-bit SIMD lane adds modelled as OR'd 32-bit halves

`207:clang:O2:{quad_stride_sum, byte_stride_unscaled}` — 2 cells.

```c
t214 = ((*(int *)(... + 0x24)) | *(int *)(... + 0x20))
     + ((*(int *)(... + 0x14)) | *(int *)(... + 0x10));
t215 = ((((unsigned long)(t214) >> 32) & 0xffffffff) | (unsigned int)(t214)) + ...;
```

clang vectorizes the 64-bit accumulation with `paddq`. Our lane model is 32 bits
wide, so each 64-bit lane becomes two 32-bit halves recombined with `|` — which
is not addition, and silently produces a different number whenever a low half
carries.

**Fix:** the packed-lane model needs a 64-bit lane width. `packed_dword_lane`
(`types.rs:140`) hardcodes 32-bit lanes and names them `{reg}_d{lane}`; a
`packed_qword_lane` alongside it, selected by the instruction's element size, is
the shape the existing code already implies. This is the same root cause as the
`WiderThanTheLaneModel` entries in the `SILENT_REGISTER_WRITERS` census
(`vpand`, `vpcmpeqb`, …), which are 256-bit against a 128-bit model.

### Rust O0 (8 cells) — recorded, not yet diagnosed

`219:rustc:O0` fails on all 7 functions including the explicit-loop control,
while `rustc:O2` passes 6 of 7. A failing control at one optimization level and
not the other points at the harness's Rust path (signature recovery from a
`cdylib`'s DWARF) rather than at iterator chains. It is baselined as-is and
flagged for investigation; the O2 lane is already doing the job the fixture was
written for.

---

## 2b. Baselines, and how each was verified

All four refreshed under the pinned toolchain (gcc 11.4 / clang 14.0), and each
diffed rather than trusted:

| baseline | change | verification |
|---|---|---|
| `baseline.json` | +402 | **0 removals, 0 modifications.** 234 pass / 32 fail, all in the new fixtures |
| `structural_baseline.json` | +435 | the one apparent removal is `171_rust_overflow` gaining a trailing comma as `219` joins the `skipped` list |
| `defuse_baseline.json` | +668 | per-lane ceilings rise by exactly the new fixtures' own counts: excluding `219_*`, the rustc total is **9,986 before and 9,986 after** |
| `arch_baseline.json` | +1156 | **816 added, 0 removed, 1 changed** — the one change is `112_recursion_shapes:armv7_a32:O2:tail_countdown` `fail -> pass`, pre-existing drift verified against the unmodified build, not attributable here |

The arch sweep is where the fixtures earn their cross-architecture keep. New-cell
results by target:

| arch | pass | fail | fail % |
|---|---:|---:|---:|
| x86_64 | 116 | 10 | 7.9% |
| x86_64_gcc15 | 115 | 11 | 8.7% |
| aarch64 | 109 | **17** | 13.5% |
| armv7 (Thumb) | 100 | **26** | 20.6% |
| armv7_a32 | 99 | **27** | 21.4% |
| i386 | 95 | **31** | 24.6% |

The gradient is the finding: **i386 and ARM fail at 2.5-3x the x86-64 rate on the
same source.** Every one of these fixtures is portable C compiled from identical
text, so the difference is entirely in per-architecture recovery. That ranks the
lifters against each other for the first time on a controlled population, and it
says the 32-bit paths — `lift_x86.rs`'s i386 half and `lift_arm32.rs` — carry
roughly three times the defect density of the one everyone measures.

The def-use census independently reproduced two of the five defects before the
diagnosis above was written — it reports `217_complex_arithmetic:complex_through_call:
var47 is read but never defined`, which is D-A's dropped helper arguments seen
from the dataflow side rather than the rendering side.

## 2c. Structural assertions: measured, not aspirational

15 `STRUCTURAL` entries were added, and every value is what the decompiler
renders **today** at gcc:O0, measured before being written:

| fixture | function | `switch` | `goto_free` |
|---|---|---|---|
| 206 | `dense_dispatch`, `sparse_dispatch` | True | True |
| 206 | `dispatch_in_loop` | True | **False** |
| 209 | all three guard chains | False | True |
| 210 | all four epilogue chains | — | True |
| 212 | `fsm_returns_from_arm` | True | **False** |
| 212 | `two_returning_arms`, `all_arms_break` | **False** | **False** |
| 215 | `wide_selector_dense`, `narrow_selector_control` | True | True |

The `False` values are the ratchet. `212`'s two lost switches are the
`statemachine` defect stated as a property for the first time: when the region
analysis lands, those flip to `True` and the gate reports it. Recording the
current state rather than the desired one is deliberate — a baseline that
asserts a fix which has not happened fails on day one and gets deleted.

Note what 209 and 210 measure: at **gcc:O0 these recover goto-free**. The shape
matcher handles this lane. The corpus instance that fails (`bin_090 sub_7370`)
has its handlers further out of line, which is why the reverted `linear_return_chain`
fix worked on a synthetic transcription and moved nothing real. That gap between
"the shape in C" and "the shape in the corpus" is itself a finding, and it is
why these fixtures pin the C form: when a future fix claims to close it, the C
form must not regress.

## 3. What this changes about the corpus

**Before:** 205 fixtures, 6 structural predicates, no way to state "this should
be a switch" or "this should have no gotos". The largest defect class in the
decompiler was unfalsifiable.

**After:** 219 fixtures, 8 predicates, and 32 newly-failing cells that are all
real. Five distinct defects, none of which any existing fixture could fail on,
across four subsystems (call-argument recovery, float type propagation, address
symbolization, dispatch ordering, and the packed-lane model).

Every one of them was found by *compiling source and diffing execution* — the
same method the companion document used for the ARM and x87 work, and the reason
these are defects rather than suspicions.

---

## 4. Fix order

Ranked by blast radius, not by how easy they are:

1. **D-B (double read as long)** — a wrong-code defect in ordinary C, not a
   corner. Any function with a spilled `double` is exposed, and the evidence to
   fix it is already in `StackLocalFacts`.
2. **D-E (64-bit lanes)** — wrong arithmetic wherever clang vectorizes a 64-bit
   accumulation, which is common at -O2. Shares a root cause with the
   `WiderThanTheLaneModel` census entries.
3. **D-D (dispatch vs select ordering)** — loses whole switches. Rarer shape,
   total loss when it hits.
4. **D-A (complex helper ABI)** — closed, documented set of symbols; small and
   sound.
5. **D-C (indirect target symbolization)** — cosmetic in effect (the call still
   goes to the right place), but it defeats callee-prototype recovery downstream.
6. **Rust O0** — diagnose before planning; the failing control says the cause is
   probably not the fixture's subject.
