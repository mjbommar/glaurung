# x86 scalar floating-point recovery — campaign log, 2026-08-12

## Where it started

104 cells across `172_float_double_widths`, `173_float_int_conversions`,
`174_float_compare_classify` and `175_float_matrix_kernel`. 100 failed. It was
the largest single defect cluster in the corpus, and the four fixtures had been
written specifically because "the execution differential rejected floating point
at signature recovery" — so nothing before them had ever made the decompiler
recover an xmm operand.

The first probe said why:

```
----- 174_float_compare_classify:gcc:O0:negate_binary32 — our C -----
float negate_binary32(float arg0) {
    /* asm: movss */
    /* asm: movss */
    /* asm: movss */
    return 0;
}
```

## What was actually missing

Counting mnemonics over the four fixtures' eight objects:

| mnemonic | count | status before |
| -------- | ----: | ------------- |
| `movss`  |   307 | **not lifted at all** |
| `movsd`  |   100 | lifted |
| `ucomiss`|    46 | not lifted |
| `cvtss2sd` | 34 | not lifted |
| `comiss` |    29 | not lifted |
| `cvttss2si` | 18 | not lifted |
| `ucomisd`|    13 | not lifted |
| `movapd` |    13 | not lifted |
| `xorpd`  |    10 | not lifted |
| `cvt*` (rest) | 16 | not lifted |

`addss`/`subss`/`mulss`/`divss` and their `sd` siblings were already lifted as
typed intrinsics — but nothing consumed them, because `ast::scalar_float_intrinsic`
only knew ARM's `vadd.f32`-style names and `scalar_vfp_register` only recognised
ARM's `s`/`d` banks.

So the arithmetic had a lifter and no lowering, and the data movement around it
had neither.

## The five layers that had to agree

1. **Lifting** (`ir/lift_x86.rs`) — `Movss`, `Movapd`/`Movupd`, `Xorpd`/`Andpd`/
   `Orps`/`Orpd`, the six `cvt*` families, and `[u]comis[sd]`.

2. **Compare semantics.** A float compare has FOUR outcomes, and the fourth is
   the point. Per Intel SDM Vol. 2A, `[u]comis*` sets `ZF=PF=CF=1` when the
   operands are unordered, and clears `OF`/`SF`/`AF` always. Lifted exactly:

   ```text
   PF = (a != a) | (b != b)      -- either is a NaN
   ZF = (a == b) | PF
   CF = (a <  b) | PF
   ```

   Unorderedness needs no predicate the LLIR lacks — `a != a` IS "a is NaN" for
   IEEE operands. Every `jb`/`jae`/`je`/`jbe`/`ja`/`jp`/`jnp` and every `setcc`
   then falls out of the existing condition machinery unchanged, which is why
   `ordered_compare_binary32` — whose fourth return value is reachable only
   through a NaN — started passing.

3. **A conversion node** (`ast::Expr::NumericConvert`). This is the one that
   needed a new AST variant, and the reason is worth keeping: the renderer's
   `write_float_expr_dec` falls back to a C99 union when it cannot prove the
   operand is already at the destination's float type, and **that union
   reinterprets the bits**. Reinterpreting is right for AAPCS-VFP's
   `vmov s0, r3` (a bit move) and catastrophically wrong for `cvtss2sd` (a value
   conversion), and only the producing instruction knows which it was. Before
   the node existed, `widen_int_to_float` returned
   `((union { unsigned int bits; float value; }){ .bits = (unsigned)((float)arg0) }).value`
   — the bit pattern of the answer, in place of the answer.

4. **The SSE parameter bank** (`ir/types_recover.rs`). x86-64 SysV passes floats
   in `xmm0..xmm7`, a bank entirely separate from the integer one — structurally
   identical to AAPCS-VFP's `s0..s15`, which already had a live-in scan and a
   mixed-signature spill-order recovery. Both were generalised
   (`float_argument_bank_slot`, `float_live_in_slots`, `mixed_entry_spill_order`)
   rather than duplicated. Before this every float parameter on x86-64 was an
   undefined live-in: `local_4 = var0` where `local_4 = arg0` belonged.

5. **The SSE result register** (`ir/abi.rs`). `xmm0` is the only place a `float`
   or `double` result can arrive, and it was missing from `return_registers`, so
   the naming pass called the recovered result an anonymous `varN` and every
   float-returning function returned zero. `ir/naming.rs` held a **verbatim
   second copy** of that table and had to be found and deleted — the copies
   drifted the moment one of them was corrected.

## Result

26 cells flipped `fail -> pass`, no regressions across 712 lanes. The float
corpus went from 4 of 104 passing to 30 of 104.

```
173_float_int_conversions   10 cells
174_float_compare_classify   4 cells
175_float_matrix_kernel     12 cells
```

Three further defects had to be fixed before the arithmetic could be reached at
all, and none of them is about float instructions:

* **`call_effects` never named the SSE bank**, so every float argument setup
  looked dead. `single_precision_horner(x, a, b)` rendered as a ONE-argument
  call. (Fixed by splitting the positional `argument_registers` — which
  `apply_locked_parameters` indexes by slot — from the may-use set. Adding the
  SSE bank to the may-use set itself was tried, cost twelve regressions in
  functions with no SSE instruction at all, and was reverted; see the note at
  `abi::call_effects`.)
* **Every call was annotated as returning `rax`**, so a float-returning call
  defined a register nobody read while the value that WAS read had no
  definition. Generalised from the existing AAPCS-VFP mechanism: candidates
  float-first, first-read wins, integer register as the fallback.
* **Any call at all made the whole function's float arithmetic opaque.**
  `dot_product_f64` reduced to `/* asm: mulsd */ /* asm: addsd */` purely
  because it also called an `int`-returning bounds check. The ARM guard is right
  for AAPCS (`s16`-`s31` are callee-SAVED) and wrong for x86-64, where every SSE
  register is caller-saved and no compiler-generated code reads a float across a
  call.

## The representation bug underneath it

**The xmm scalar view and the xmm dword-lane view did not alias.** `movss` and
the SSE arithmetic write the whole-register name (`xmm0`); `movd`, `movq`,
`pxor`, `movaps` and the packed ops write four separate lane names
(`xmm0_d0..d3`). They are the same bits and the LLIR treats them as unrelated
values. So:

```text
cvtsi2sd  -> defines xmm0            (scalar)
movq %xmm0,%rax -> reads xmm0_d1:xmm0_d0   (lanes, still holding the pxor zero)
```

`widen_long_to_double` returns 0 for exactly this reason, and every function in
174 that reads a float's bit pattern (`sign_bit_of_binary32`, `classify_binary32`,
`absolute_binary32`, `zero_sign_from_product`) is the same shape.

Fixed by `lift_x86::synchronise_xmm_views`: any instruction that writes lane 0
or 1 also redefines the whole-register name, and MOVQ's GPR forms read the
scalar view that every producer now defines. A lane-for-lane REGISTER move
carries the source's scalar view across instead of rebuilding the destination's
from lanes a `movss` never wrote.

That change needed one guard elsewhere. The synchronisation op is a definition
of `xmm0`, and the result recovery counted it as a returned value — every
vectorised `void` function (clang -O2 `mem_copy`) started reporting an unknown
result where it had correctly reported none. It is not a value this function
produced; it is the lanes it just wrote, under their other name, and is skipped
as an output trial.

## What is still broken

`negate_binary32` and `absolute_binary32` are `xorps`/`andps` against a 16-byte
sign mask in `.rodata` — a readonly-data fold plus a sign-bit idiom, independent
of everything above. `181_compensated_summation` still fails 18 of 20 cells:
`subsd` at binary64 is largely unrecovered, which is exactly what that fixture
was written to expose.

## A trap worth not re-entering

`decompile_many`'s `timeout_ms` was extended to bound the RENDERING loop, not
just the CFG walk. It was reverted, and the reason is recorded at the site:
`tools/diff_decompile.decompiled_many_c` calls it with no `timeout_ms`, so it
takes the 5 s default; under CPU load the budget expired mid-set and the
unrendered functions came back as an explanatory stub. The harness compiled the
stub, found no definition, and reported
`151_wide_branch_ladder:clang:O0:big151_flat_cascade` as
`undefined symbol: big151_flat_cascade`.

Same build, same seed: passes idle, fails under sixteen spinners. A wall clock
over rendering converts "the machine is busy" into "this function decompiles to
nothing", and it could not have caught the spin that motivated it anyway — that
spin was *inside* `refine_float_copy_types`, where no between-pass check
reaches. The real fix was the pass's fixed-point proof.
