# Decompiler defect register — 2026-08-05

A per-defect register: what is broken, on which lanes, what is proven, and what
is still guesswork. Companion to
[`armv7-real-defects-2026-08-05.md`](armv7-real-defects-2026-08-05.md), which
carries the narrative and the root-cause write-ups; this file is the list.

Every entry below is machine-derived from `tools/arch_roundtrip.py`, not
hand-curated. Regenerate with:

```bash
python3 tools/arch_roundtrip.py --check --jobs 8        # the ratchet
python3 tools/arch_roundtrip.py --width-audit --jobs 8  # REAL vs UNSEPARABLE, 32-bit lanes
python3 tools/arch_roundtrip.py --arch aarch64 --json --jobs 8
```

If this file and the harness disagree, the harness is right and this file has
rotted.

## Why these numbers are trustworthy

`arch_roundtrip.py` is an **execution differential**: it rebuilds the recovered C
for the host, calls it and the original with identical seeded vectors, and
compares every full-width return and mutated buffer. It never invokes capstone
and never computes `byte_match`.

That matters, because on the same day this register was written we found
DecBench's `byte_match` to be *unsound* on ARM — see M1–M3 below. This harness
was unaffected and stayed correct throughout.

## Lane summary

| lane | judged | pass | fail | ABI-incomparable | correctness |
|---|---|---|---|---|---|
| `x86_64` | 328 | 328 | 0 | 0 | **100.0%** (CONTROL — must stay clean) |
| `i386` | 256 | 232 | 24 | 16 | 90.6% |
| `aarch64` | 328 | 274 | 54 | 0 | 83.5% |
| `armv7` | 256 | 210 | 46 | 16 | 82.0% |

The 32-bit lanes execute the recovered C at *host* pointer width, so their
failures are split by `--width-audit` into **REAL** (recovered C names no
width-varying type, so the host rebuild genuinely is the 32-bit semantics) and
**UNSEPARABLE** (this apparatus cannot tell defect from artefact). Only REAL
defects are registered below. armv7 has 27 UNSEPARABLE and i386 has 10; they are
*not* known-good.

`aarch64` needs no such adjudication — 64-bit, zero ABI-incomparable — so all 54
of its failures are real.

## The finding that reframes the list

**12 of the 19 armv7 REAL defects also fail on `i386`, which is x86, not ARM.**
They are 32-bit defects, not ARM defects. Only **one** is armv7-exclusive.

This corrects the earlier framing in the companion document, which grouped most
of them as ARM problems under a "pointer/array-heavy" heading. That heading
described the fixtures, not the cause, and the cause is mostly ILP32.

Practical consequence: fixes aimed at D1/D2 should go in width-aware or
architecture-neutral code and will pay off on two lanes at once. Only D3/D4 argue
for touching ARM-specific code.

---

## Open defects — armv7 REAL (19)

### D1 — fails on ALL THREE non-control lanes (5)

Arch-independent. **Caveat:** the `x86_64` control is built with *pinned* gcc 11.4.0 while these three lanes use host gcc 15.2.0, so these may be a gcc-15 codegen shape rather than an architecture gap. Rebuild the control with gcc 15 before concluding.

| fixture | opt | function | lanes | |
|---|---|---|---|---|
| `04_switch_shapes` | O2 | `negative_cases` | armv7 · i386 · aarch64 |  |
| `04_switch_shapes` | O2 | `sparse_shared_tail` | armv7 · i386 · aarch64 |  |
| `10_cpp_runtime_shapes` | O0 | `cpp_lambda_capture` | armv7 · i386 · aarch64 |  |
| `22_dijkstra` | O2 | `dijkstra_dense` | armv7 · i386 · aarch64 |  |
| `23_topological_sort` | O2 | `topological_sort` | armv7 · i386 · aarch64 |  |

### D2 — both 32-bit lanes, not aarch64 (7) — ILP32, NOT ARM

| fixture | opt | function | lanes | |
|---|---|---|---|---|
| `03_loop_shapes` | O0 | `dowhile_atleastonce` | armv7 · i386 |  |
| `10_cpp_runtime_shapes` | O0 | `cpp_ctor_dtor` | armv7 · i386 |  |
| `10_cpp_runtime_shapes` | O0 | `cpp_raii_guard` | armv7 · i386 |  |
| `13_loop_early_exit` | O0 | `classify_run` | armv7 · i386 |  |
| `18_binary_heap` | O0 | `heap_pop` | armv7 · i386 |  |
| `30_finite_difference` | O0 | `heat_step_1d` | armv7 · i386 |  |
| `30_finite_difference` | O2 | `heat_step_1d` | armv7 · i386 |  |

### D3 — armv7 only (1) — genuinely ARM32-specific

| fixture | opt | function | lanes | |
|---|---|---|---|---|
| `18_binary_heap` | O2 | `heap_pop` | armv7 |  |

### D4 — armv7 + aarch64, not i386 (ARM family)

| fixture | opt | function | lanes | |
|---|---|---|---|---|
| `07_packet_parser` | O0 | `parse_packet` | armv7 · aarch64 |  |
| `08_indirect_dispatch` | O2 | `tail_dispatch` | armv7 · aarch64 |  |
| `20_graph_bfs` | O2 | `graph_bfs` | armv7 · aarch64 |  |
| `21_graph_dfs` | O2 | `graph_dfs` | armv7 · aarch64 |  |
| `22_dijkstra` | O0 | `dijkstra_dense` | armv7 · aarch64 |  |
| `25_kmp_search` | O2 | `kmp_search` | armv7 · aarch64 |  |
---

## Open defects — aarch64 (54)

All real (64-bit, no width confound, zero ABI-incomparable). **Not diagnosed** —
verdicts only; no recovered C inspected. 11 overlap the armv7 REAL list and are
registered above; the remaining 43 are aarch64-only:

| fixture | opt | function |
|---|---|---|
| `02_integer_widths` | O0 | `rotl16_3` |
| `02_integer_widths` | O0 | `trunc_u16_after_mul` |
| `02_integer_widths` | O2 | `mul_widen` |
| `02_integer_widths` | O2 | `rt_u32` |
| `03_loop_shapes` | O2 | `for_sum` |
| `03_loop_shapes` | O2 | `loop_continue` |
| `03_loop_shapes` | O2 | `mutate_reverse` |
| `05_cleanup_and_state_machine` | O0 | `process` |
| `05_cleanup_and_state_machine` | O2 | `process` |
| `06_calling_conventions` | O0 | `fib` |
| `06_calling_conventions` | O2 | `fact_mod` |
| `06_calling_conventions` | O2 | `fib` |
| `07_packet_parser` | O0 | `validate_header` |
| `07_packet_parser` | O2 | `parse_packet` |
| `07_packet_parser` | O2 | `validate_header` |
| `08_indirect_dispatch` | O0 | `dispatch` |
| `08_indirect_dispatch` | O0 | `dispatch_switch` |
| `08_indirect_dispatch` | O0 | `tail_dispatch` |
| `08_indirect_dispatch` | O2 | `dispatch` |
| `10_cpp_runtime_shapes` | O2 | `cpp_ctor_dtor` |
| `10_cpp_runtime_shapes` | O2 | `cpp_raii_guard` |
| `11_call_shapes` | O0 | `call_accumulate_bytes` |
| `11_call_shapes` | O0 | `call_twice_and_combine` |
| `11_call_shapes` | O2 | `call_chain_in_loop` |
| `11_call_shapes` | O2 | `call_fold_wide_result` |
| `11_call_shapes` | O2 | `call_into_spill` |
| `12_loop_rotation` | O2 | `factorial_while` |
| `12_loop_rotation` | O2 | `find_first_set` |
| `12_loop_rotation` | O2 | `nested_rotated` |
| `14_flag_effects` | O2 | `shift_until_zero` |
| `15_binary_search_tree` | O2 | `bst_inorder_checksum` |
| `15_binary_search_tree` | O2 | `bst_search` |
| `16_red_black_tree` | O0 | `rb_validate` |
| `16_red_black_tree` | O2 | `rb_validate` |
| `17_hash_table` | O0 | `hash_insert` |
| `17_hash_table` | O0 | `hash_lookup` |
| `19_disjoint_set` | O0 | `dsu_find` |
| `19_disjoint_set` | O0 | `dsu_union` |
| `20_graph_bfs` | O0 | `graph_bfs` |
| `21_graph_dfs` | O0 | `graph_dfs` |
| `23_topological_sort` | O0 | `topological_sort` |
| `25_kmp_search` | O0 | `kmp_search` |
| `28_euler_ode` | O2 | `euler_decay_q16` |

---

## Open defects — i386 REAL (14)

12 are shared with armv7 and registered as D1/D2 above. Two are i386-only:

| fixture | opt | function |
|---|---|---|
| `04_switch_shapes` | O2 | `dense_compute` |
| `24_merge_sort` | O2 | `merge_sort_i32` |

---

## Diagnosed but NOT fixed

### X1 — 32-bit modular wrap rendered non-modularly
**Lanes:** armv7 + i386 (D2 `dowhile_atleastonce`, and likely others).
**Status:** root cause proven; fix deliberately deferred.

The recovered index reads `arg0[(i + 0x40000000) - 1]` where the source says
`p[i - 1]`. The constant is genuinely in the binary — gcc emits
`add r3,r3,#0x40000000; subs r3,#1; lsls r3,r3,#2`, adding 2^30 knowing it
shifts clean out, because `(i + 2^30 - 1) * 4 == (i - 1) * 4 (mod 2^32)`.

The recovery is faithful at 32 bits and wrong at any other width: rebuilt at host
width the term does not truncate and the index runs off the array.

Fix is the provable identity `(x + C) << s == x << s` when `C * 2^s ≡ 0 (mod
2^W)`. **Not applied** because `const_fold::fold_constants(f: &mut Function)` has
neither an architecture nor a width, and at `W = 64` the same rewrite is plainly
wrong — `0x40000000 << 2` is a legitimate 64-bit value. Folding it unguarded
would introduce exactly the silent-wrong-answer class this register catalogues.
`fold_typed_comparison_extensions(f, tm)` shows the width-aware shape it needs.

### X2 — ARM32 stack frames do not promote
**Lanes:** armv7 (affects every -O0 function, not only registered defects).
**Status:** root cause proven; one fix attempted and reverted.

`stack_locals.rs:31` omits ARM32's `r7`/`r11` from `STACK_BASES`, so an armv7
frame never splits into named locals and stays one opaque byte array
(`unsigned char local_68[104]`). Consequence: `dead_stores::
prune_callee_saved_spills` matches a spill to a *promoted* slot, so ARM's
`store (&local_68 + 100) = %fp` matches nothing and the callee-save idiom is
never elided — which is why `lr` and the saved frame register are read undefined
in essentially all armv7 output.

Registering `r7`/`r11` as stack bases was tried: **82.0% -> 76.2%, 15
regressions**, all on functions with incoming *stack* arguments, which sit at
positive displacement from `r7` exactly like locals. A frame-extent boundary is
required. The promotion half worked.

### X3 — ARM aggregates get no DWARF extent
**Lanes:** armv7. **Status:** proven inert; same blocker as X2.

ARM has no `DwarfStackBase::CallFrameCfa` arm where x86-64, i386 and AArch64 all
do, and this is the common path — gcc emits
`DW_AT_frame_base: DW_OP_call_frame_cfa` for ARM exactly as for x86-64. So every
ARM aggregate hint is dropped and `graph_bfs`'s `int32_t queue[16]` has no
recovered extent, where x86-64 recovers `local_60[64]`.

Adding the arm does **not** fix it: AAPCS pushes no return address, so the CFA is
the entry stack pointer, and `promote_*` filters hints through
`is_active_stack_base` — which contains neither `entry_sp` nor `r7`. Emitting
`("entry_sp", 0)` was tried and changed nothing. **X2 and X3 are one blocker:**
the hint vocabulary and the slot vocabulary both need the entry anchor.

### X4 — tail call through a resolved function table loses its arguments
**Lanes:** armv7 (D4 `08_indirect_dispatch:O2:tail_dispatch`).
**Status:** partially diagnosed.

The table now resolves at O2, but `bx r3` recovers as a call with no arguments:
`((long (*)(void))(ops[var0]))()`. `recover_tail_calls_in_body` *does* handle
`IndirectGoto { target: FunctionTableEntry }`; the gap is that the preceding
`mov r0,r1` / `mov r1,r2` set `has_local_setup`, so args are left to
`reconstruct_args`, which recovers none because a `FunctionTableEntry` target
carries no arity — even though all of its targets share one prototype.

---

## Fixed this session

### Decompiler (glaurung) — armv7 78.9% -> 82.0%, zero regressions

| id | defect | site | pinned by |
|---|---|---|---|
| F1 | Thumb-2 predicated flag-writes executed unconditionally. `make_conditional` bailed on any multi-op lift; a `cmp` is 5 flag writes, so gcc's conditional-compare idiom for `&&` ran unpredicated and erased the first operand. | `ir/lift_arm32.rs` | `a_predicated_compare_does_not_clobber_the_flags_it_is_predicated_on` |
| F1b | A predicated instruction may write the flag it is predicated on (`it ne` / `cmpne` both touch Z); committing against the live flag gated later selects on an already-re-selected condition. Caught as a live regression by `--check`, not by reading. | `ir/lift_arm32.rs` | `a_predicate_written_by_its_own_instruction_is_snapshotted_first` |
| F2 | Arch-blind `parent64` rewrote ARM32's `lr` to AArch64's `x30` at width 64. Measured safe: capstone emits 42 `x29` / 31 `x30` / **zero** `lr`\|`fp` for AArch64. | `ir/ssa.rs` | doc + measurement |
| F3 | The relocation-proven `ops` table was collected for armv7 and never matched: `constant_address` rejected bare `Expr::Const` (ARM32 literal pool) and its `Add` arm rejected `Expr::Addr` on the offset side; `is_table_base` held a second, shorter notion of "names an address". | `ir/function_tables.rs` | `arm32_literal_pool_table_base_resolves_to_the_table`, `a_constant_base_that_is_not_the_table_does_not_match` |
| F4 | `is_frame_base` listed x86/AArch64 but not ARM32's `r7`/`r11`, and compared whole names so the SSA-suffixed `r7#1` never matched. ARM32 pointer **parameters** were typed `int` — invisible at 32 bits, lethal when rebuilt at 64. | `ir/types_recover.rs` | `frame_bases_cover_arm32_and_ignore_the_ssa_suffix` |
| F5 | DWARF register 7 is `r7` and 11 is `r11`; both were mapped to the name `fp`. Factual correction, **unexercised** by the corpus — kept, but not evidence-backed. | `python_bindings/ir.rs` | none (see caveat) |

### Benchmark measurement (DecBench) — `byte_match` was unsound on ARM

Uncommitted in `/nas4/data/workspace-infosec/decbench` on top of `efc5d5a`;
6 regression tests in `tests/test_arm_thumb_extraction.py`.

| id | defect |
|---|---|
| M1 | `_elf_function_bytes` sliced Thumb functions at the raw odd `st_value` (the ARM ELF ABI stores Thumb-ness in bit 0) — every Thumb function read one byte late *and* one byte into the next. |
| M2 | `_elf_object_function` had the identical defect on the **recompiled** side, so both halves of every comparison were misaligned. |
| M3 | `capstone_arch_mode` defaulted to ARM mode on Thumb code. Added `elf_function_is_thumb()` (reads the symbol T-bit — the ABI states the encoding outright) and wired it in. |

**Why this mattered more than it looks.** Capstone does not fail on the wrong
mode; it returns confident nonsense, or nothing. `byte_match.py:163` reads:

```python
if not lines_a and not lines_b:
    return 1.0, 0
```

A short Thumb function decoded as ARM disassembles to `[]` on **both** sides, so
the metric awarded a **perfect 1.0**. That is the entire explanation for Ghidra's
1.0000 on `libopencm3::lcd_command` — two undecodable byte streams scoring
perfect against each other, not a good decompilation. Every published ARM
`byte_match` figure is therefore suspect, ours and every other tool's. Worth
upstreaming; **not** on the critical path for any defect in this register, and no
fix here should be validated against it.

---

## Coverage gaps in the harness itself

- **No `-marm` (A32) lane.** The armv7 lane is `-mthumb` only, so every claim
  about `r11` is unfalsifiable by the gate. This is not hypothetical: a theory
  that `r11` shared `r7`'s frame-pointer sign convention survived review and was
  only disproven by disassembling an A32 build by hand. A32 does
  `add fp, sp, #0` *before* `sub sp`, so its locals are at negative displacement
  like x86's `rbp`; only Thumb's `r7` inverts. **Add this lane before reworking
  ARM frame handling.**
- **The control uses a different compiler.** `x86_64` is pinned to gcc 11.4.0
  while `i386`/`armv7`/`aarch64` use host gcc 15.2.0, so a defect on all three
  non-control lanes (D1) may be a gcc-15 codegen shape rather than an
  architecture gap.
- **32-bit lanes are not executed at 32 bits.** The differential worker is
  64-bit CPython driving `ctypes.CDLL`, which refuses a 32-bit object. The
  residue this leaves is quantified by `--width-audit`, not hand-waved.
