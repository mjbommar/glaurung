# The real armv7 semantic defects

**Date:** 2026-08-05 (started at 26 defects; **19 remain**)
**Harness:** `tools/arch_roundtrip.py`
**Status of the list:** reproducible, machine-derived, not hand-curated.
**Status of the diagnoses:** four root causes found, fixed and pinned with
tests; one more located but deliberately not fixed (see *Known and not fixed*);
the rest explicitly marked below as undiagnosed. Do not read a cluster heading
as a diagnosis — read the per-cluster "evidence" line.

## Progress

| | armv7 pass | armv7 correctness | REAL defects |
|---|---|---|---|
| start of session | 202 / 256 | 78.9% | 26 |
| now | **210 / 256** | **82.0%** | **19** |

Seven functions were fixed by four root-cause changes, with **zero regressions**:
the `x86_64` control lane held at 100.0% throughout, `cargo test --lib` is
1737/1737, and `tools/fixture_harness.py` is 656 pass / 0 fail. The baseline in
`baseline.json` has been refreshed, so `--check` is green at the new numbers.

Every fix was verified by execution, not by reading the recovered C. Three of
the four also improved functions in the UNSEPARABLE pile (`sc_mixed`,
`hash_insert`, `csr_matvec`), which is weak evidence that pile contains real
defects too rather than only width artifacts.

**The recurring shape.** Every one of the four was an
architecture-specific list or fallback that quietly did the wrong thing instead
of failing: `make_conditional`'s `return ops` for multi-op lifts,
`ssa::parent64`'s AArch64 fallback swallowing ARM32's `lr`, `constant_address`
accepting too few literal spellings, and `is_frame_base` naming every
architecture except ARM32. None raised an error. Each produced confident, wrong
C. When looking for the remaining 19, grep for lists of register names and for
`_ => None` / `return ops` fallbacks before reading anything else.

---

## Why this list is trustworthy, and why that needed saying

On 2026-08-05 we found that DecBench's `byte_match` was *unsound on ARM*, not
merely noisy. Three defects compounded:

1. `binfmt._elf_function_bytes` sliced Thumb functions at the raw odd
   `st_value` (the ARM ELF ABI stores Thumb-ness in bit 0), reading one byte
   late and one byte into the next function.
2. `binfmt._elf_object_function` had the identical defect on the **recompiled**
   side, so both halves of every comparison were misaligned.
3. `capstone_arch_mode` defaulted to ARM mode on Thumb code.

Capstone does not fail loudly on the wrong mode; it returns confident nonsense,
or nothing. And `byte_match.py:163` reads:

```python
if not lines_a and not lines_b:
    return 1.0, 0
```

A short Thumb function decoded as ARM disassembles to `[]` on **both** sides, so
the metric awarded a **perfect 1.0**. That is the entire explanation for
Ghidra's 1.0000 on `libopencm3::lcd_command` — garbage matching garbage.

**None of that touches this document.** `tools/arch_roundtrip.py` is an
*execution* differential: it rebuilds the recovered C for the host, calls it and
the original with identical seeded vectors, and compares every full-width return
and mutated buffer. It never invokes capstone and never computes `byte_match`.
It was correct while the byte metric was broken, and the 26 defects below were
measurable the whole time.

Three further properties make the list actionable rather than suggestive:

- **The `x86_64` control lane is 100.0% clean** (328/328). Every failure below is
  therefore ARM-specific, not a general decompiler bug leaking into an ARM lane.
- **The armv7 lane is `-mthumb`** (`arm-linux-gnueabihf-gcc -march=armv7-a
  -mfpu=vfpv3-d16 -mthumb`), so it exercises Thumb-2 — the exact encoding
  DecBench mis-measured.
- **`--width-audit` separates real defects from the ILP32/LP64 confound.** The
  recovered C is executed at *host* pointer width, so a 32-bit lane could fail
  for reasons that are artifacts. The audit splits failures into those whose
  recovered C names a width-varying type (UNSEPARABLE — this apparatus cannot
  tell defect from artifact) and those that name none (REAL — a 64-bit rebuild
  of such a fragment is value-identical to a 32-bit one, so the failure is
  semantic). **Only the 26 REAL ones are listed here.** The 28 UNSEPARABLE ones
  are a separate, genuinely-unknown pile; see the last section.

Full matrix at the time of writing (matches the committed baseline exactly):

| lane | judged | pass | fail | incomparable | correctness |
|---|---|---|---|---|---|
| `x86_64` | 328 | 328 | 0 | 0 | **100.0%** (CONTROL — must be clean) |
| `i386` | 256 | 232 | 24 | 16 | 90.6% |
| `aarch64` | 328 | 274 | 54 | 0 | 83.5% |
| `armv7` | 256 | 202 | 54 | 16 | **78.9%** |

Note `aarch64`: 54 failures with **zero** ABI-incomparable functions and no
width confound at all, because it is 64-bit. Those 54 need no `--width-audit`
adjudication — they are all real. ARM as a family is therefore ~80 confirmed
semantic defects against x86-64's zero. This document covers only the armv7 26.

---

## How to test

### Reproduce the whole list

```bash
cd /nas4/data/binary-analysis/wt-globals
python3 tools/arch_roundtrip.py --width-audit --jobs 8
```

Prints, per 32-bit lane, the REAL / UNSEPARABLE / NON-PORTABLE split with every
member named as `fixture:opt:function`. This is the authority for the list
below; if it disagrees with this file, it is right and this file has rotted.

### Run one fixture's lane

```bash
python3 tools/arch_roundtrip.py --arch armv7 --opt O2 01_conditional_polarity
```

Both the `armv7` lane and the `x86_64` control are always built and reported, so
you always see whether a change broke the control. Granularity here is
`fixture:arch:opt` — the tool takes fixture stems positionally, not function
names.

### Get per-function verdicts

```bash
python3 tools/arch_roundtrip.py --arch armv7 --opt O2 --json 01_conditional_polarity
```

```json
{"01_conditional_polarity:armv7:O2": {"sc_and": "fail", "sc_or": "fail", "ternary": "pass", ...},
 "01_conditional_polarity:x86_64:O2": {"sc_and": "pass", "sc_or": "pass", ...}}
```

This is how to confirm a single function without reading the summary table, and
how to see the control's verdict for the same function side by side.

### Look at the actual recovered C

The harness judges but does not show you the code. To see it:

```bash
S=/tmp/armv7                 # any scratch dir
mkdir -p $S
# Build exactly as the harness does (tools/arch_roundtrip.py ARCHES["armv7"]):
arm-linux-gnueabihf-gcc -march=armv7-a -mfpu=vfpv3-d16 -mthumb -O2 -g -shared -fPIC \
    tests/decompiler_fixtures/src/01_conditional_polarity.c -o $S/f.so
./.venv/bin/glaurung decompile $S/f.so --func sc_and --style decbench

# ...and the control, for the side-by-side that makes the defect obvious:
gcc -O2 -g -shared -fPIC \
    tests/decompiler_fixtures/src/01_conditional_polarity.c -o $S/c.so
./.venv/bin/glaurung decompile $S/c.so --func sc_and --style decbench
```

For C++ fixtures (`10_cpp_runtime_shapes`) substitute `arm-linux-gnueabihf-g++`
and `g++`.

### Read the machine code

```bash
arm-linux-gnueabihf-objdump -d --disassemble=sc_and $S/f.so
```

Necessary for any Thumb-2 predication defect — the IT-block structure is
invisible in the recovered C, which is precisely the problem.

### Ratchet before committing

```bash
python3 tools/arch_roundtrip.py --check --jobs 8      # full matrix; no filters allowed
```

`--check` rejects `--arch`/`--opt`/fixture filters by design: a ratchet you can
narrow is a ratchet that silently stops covering the control lane. A fix must
report `ARCH ROUND-TRIP: matches the baseline exactly` or better, and must
never move `x86_64` off 100.0%.

---

## Cluster A — Thumb-2 predicated flag-writes (2 defects) — **FIXED**

| fixture | opt | function | source |
|---|---|---|---|
| `01_conditional_polarity` | O2 | `sc_and` | `int sc_and(int x, int y)` — `:76` |
| `01_conditional_polarity` | O2 | `sc_or` | `int sc_or(int x, int y)` — `:83` |

These are `@smoke` canaries. They pass on `x86_64` at the same opt level. They
are four lines each. If you fix one thing on this page, fix this.

**Evidence: execution-verified, disassembly-verified, root cause located.**

Source:

```c
int sc_and(int x, int y) {
    if (x > 0 && y > 0) return 1234;
    return 4321;
}
```

Recovered from armv7/O2 — note `arg0` is **never tested**:

```c
int sc_and(int arg0, int arg1) {
    return ((arg1 <= 0) ? 0x10e1 : 1234);       /* 0x10e1 == 4321 */
}
```

Recovered from the x86-64 control at the same opt level, which tests both:

```c
int sc_and(int arg0, int arg1) {
    if (((arg0 == 0) | ((long)(arg0) < 0))) return 0x10e1;
    ret = 1234;
    if ((((arg1 == 0) | ((long)(arg1) < 0)) == 0)) return ret;
    return 0x10e1;
}
```

Executed differential over `{-5, 0, 5}²`:

```
MISMATCH (-5,5): orig=4321 rec=1234
MISMATCH ( 0,5): orig=4321 rec=1234
```

Why. gcc compiles the short-circuit `&&` into Thumb-2's conditional-compare
idiom:

```
 540:  2800        cmp    r0, #0
 542:  bfc8        it     gt          <- arms predication for the next slot
 544:  2900        cmpgt  r1, #0      <- CONDITIONAL compare. If r0 <= 0 this does
                                         NOT execute, so the flags still hold
                                         arg0's LE result.
 54e:  bfd8        it     le
 550:  4618        movle  r0, r3
 552:  4770        bx     lr
```

The flags reaching `movle` encode *both* conditions — that is the whole trick.
IT blocks themselves **are** modelled (`src/ir/lift_arm32.rs:2285-2440`, with
tests at `:3062` and `:3094`); predicated instructions become `Op::Ite` selects.
The defect is narrower. `src/ir/lift_arm32.rs:2306`:

```rust
fn make_conditional(ops: Vec<Op>, cond: VReg, inverted: bool) -> Vec<Op> {
    ...
    if ops.len() != 1 {
        return ops;            // <-- line 2315
    }
```

with the doc comment conceding: *"multi-op or store-only lifts fall back to
executing unconditionally (a documented approximation)."*

A `cmp` writes N, Z, C and V — **four ops**. So it takes the `ops.len() != 1`
branch and is emitted **unconditionally**, clobbering the flags that carried
`arg0`'s result. Only `arg1` survives, which is exactly the recovered C.

This is the same shape as every other defect this project has chased: a helper
that silently degrades instead of refusing, and the degradation is a plain
`return ops`. It is not a missing feature; it is a fallback that is wrong
whenever the predicated instruction writes flags.

**The fix (landed).** `make_conditional` now delegates any multi-op lift to a
new `predicate_sequence`, which runs the instruction into scratch and then
commits each architectural write through an `Op::Ite`. Writes to `Temp` are left
alone (instruction-internal scratch, dead outside the lift); reads are rewritten
so a sequence that consumes its own earlier writes — `O = S xor Slt` in
`cmp_flag_ops` does exactly that — computes from the new value, not the stale
one. Only stores and control transfers still fall through unconditionally; the
IR has no predicated store, so that residue is now narrow and named instead of
being *every* multi-op lift.

**One subtlety, caught as a live regression rather than by reasoning.** A
predicated instruction may write the very flag it is predicated on, and the
conditional-compare idiom routinely does — `it ne` / `cmpne` predicates on Z and
writes Z. Committing the selects against the live flag let the Z commit land
first, so every later select was gated on an already-re-selected Z. `fsm`'s
guard recovered as `((arg0==0) ? (arg0==0) : (arg1==0)) ? ...` and the lane went
`pass -> fail`. `predicate_sequence` now snapshots the predicate into a temp
before any commit. **The ratchet caught this; reading the diff did not.** Run
`--check`, not just the fixture you are working on.

Pinned by `a_predicated_compare_does_not_clobber_the_flags_it_is_predicated_on`
and `a_predicate_written_by_its_own_instruction_is_snapshotted_first` in
`src/ir/lift_arm32.rs`. Also fixed `sc_mixed`, `17_hash_table:O2:hash_insert`
and `26_sparse_matrix:O2:csr_matvec` from the UNSEPARABLE pile.

---

## Cluster B — indirect dispatch (4 defects) — **3 of 4 FIXED**

| fixture | opt | function | status |
|---|---|---|---|
| `08_indirect_dispatch` | O0 | `dispatch` | **fixed** |
| `08_indirect_dispatch` | O2 | `dispatch` | **fixed** (now UNSEPARABLE, not REAL) |
| `08_indirect_dispatch` | O0 | `tail_dispatch` | **fixed** |
| `08_indirect_dispatch` | O2 | `tail_dispatch` | **still failing** — see below |

Source: `int dispatch(int tag, int a, int b)` — `:46`;
`int tail_dispatch(int tag, int a, int b)` — `:69`.

**Two defects were present. The caveat in the original version of this document
— that the `x30` leak was confirmed but probably not load-bearing — was
correct: fixing it alone changed no verdict, and the table address was what
actually mattered.**

Recovered from armv7/O0:

```c
int dispatch(int arg0, int arg1, int arg2) {
    unsigned char local_18[24];
    long var0;
    long var11;
    long x30;                                            /* (1) */
    *(int *)((&local_18[0] + 16)) = var0;
    *(int *)((&local_18[0] + 20)) = x30;                 /* (1) */
    if ((arg0 < 0))  { arg0 = -1; return -1; }
    if ((4 < arg0))  { arg0 = -1; return -1; }
    var11 = ((long (*)(int, int))(*(int *)((0x20028 + (arg0 * 4)))))(arg1, arg2);  /* (2) */
    arg0 = var11;
    return var11;
}
```

Two observable defects:

**(1) `x30` in an ARM32 function — the AArch64 register model is leaking.**
`x30` is the *AArch64* link register; ARM32's is `lr`/`r14`, and it is 32 bits
wide, not 64. Confirmed to the line:

- `src/ir/regview.rs:40` — `pub enum Arch { X86_64, AArch64 }`. **There is no
  ARM32 variant at all.**
- `src/ir/regview.rs:224` — `v.push(mk("lr", "x30", 0, 64));` — `lr` is
  declared an alias of `x30` at **width 64**, which is true for AArch64 and
  false for ARM32.
- `src/ir/ssa.rs:125` — `parent64` consults `X86_64`, then falls back to
  `AArch64`, and stops. There is no ARM32 table to consult.

So on ARM32, `lr` is canonicalized into AArch64's `x30` at 64 bits, and is then
read undefined. This is EPIC 4's premise, confirmed rather than asserted.

*Fixed* in `ssa::parent64`, which now declines the names the two ARM
architectures spell alike and size differently (`ARM32_AMBIGUOUS = ["lr","fp"]`).
`regview`'s AArch64 table still declares the aliases truthfully — a descriptor
should answer the architectural question correctly; it is the *arch-blind*
lookup that must be conservative, because `LlirFunction` carries no
architecture to consult. Declining costs AArch64 nothing, and that is measured
rather than assumed: disassembling the fixture corpus yields 42 `x29` and 31
`x30` and **zero** `lr`/`fp`, so capstone never hands AArch64 one of these
names. **This fix alone flipped no verdict** — the `lr` save is inert at
execution time — but it removes a wrong name at a wrong width from every ARM32
function.

**(2) A hardcoded absolute address for the ops table — this was the
load-bearing one.** `*(int *)(0x20028 + arg0 * 4)` bakes in a link-time address
from a *PIC shared object*; any rebuild dereferences a wild pointer.

The machinery to fix this already existed and already worked on x86-64, which
materialises `static void (*ops[5])(void)` with `extern` declarations for each
handler. `collect_function_pointer_tables` was collecting the armv7 `ops` table
*correctly* — all five `R_ARM_RELATIVE` slots resolved to the right names — and
then the load was never matched to it. Two independent gaps in the address
matcher, both found only by dumping what the matcher actually saw:

- `constant_address` accepted `Addr`/`Named`/`Reg`/`Add` but **not a bare
  `Expr::Const`**. ARM32 reaches its own data through the literal pool
  (`ldr r3,[pc,#N]` + `add r3,pc`), which the lifter resolves to a plain
  integer; x86-64's RIP-relative `lea` produces an `Addr`, so the gap was
  invisible there.
- its `Add` arm accepted only `Expr::Const` on the offset side, and the real
  AST is `Bin { Add, lhs: Reg(r3#3), rhs: Addr(0x4a0) }` — the lifter typed the
  pool value as `Addr`. Both spellings denote the same integer; which one a
  displacement gets is a lifter detail this pass must not depend on.

`is_table_base` also carried its own shorter list of "shapes that name an
address", so a base `constant_address` could resolve was a table base to one
function and not the other. Two answers to one question is how the gap
survived; it now delegates.

armv7 `dispatch` recovers as `ops[arg0]` with the full table, identical to
x86-64. Pinned by `arm32_literal_pool_table_base_resolves_to_the_table` and
`a_constant_base_that_is_not_the_table_does_not_match` in
`src/ir/function_tables.rs`.

**Still failing: `O2:tail_dispatch`.** The table now resolves at O2 too, but two
further defects remain, both visible in the disassembly
(`objdump -d --disassemble=dispatch`):

```
 414:  mov   ip, r0        ; tag
 416:  mov   r0, r1        ; a -> arg0
 420:  mov   r1, r2        ; b -> arg1
 424:  ldr.w r3, [r3, ip, lsl #2]
 428:  bx    r3            ; TAIL CALL through the table
```

- the `bx r3` tail call recovers as a plain call followed by `return -1;`,
  losing the tail-call's result; it should be `return ops[tag](a, b);`
- the argument setup (`mov r0,r1` / `mov r1,r2`) is not recovered, so the call
  renders as `((long (*)(void))(ops[var0]))()` — no arguments

That is a tail-call-through-a-function-table shape. `recover_resolved_tail_calls`
runs after `resolve_function_table_entries` (correct order), so the question is
whether it handles an `IndirectGoto` whose target is a `FunctionTableEntry`.
Not investigated further.

---

## Cluster C — C++ runtime shapes (4 defects) — **1 of 4 FIXED**

| fixture | opt | function | status |
|---|---|---|---|
| `10_cpp_runtime_shapes` | O0 | `cpp_move` | **fixed** — `:144` |
| `10_cpp_runtime_shapes` | O0 | `cpp_ctor_dtor` | still failing — `:67` |
| `10_cpp_runtime_shapes` | O0 | `cpp_lambda_capture` | still failing — `:116` |
| `10_cpp_runtime_shapes` | O0 | `cpp_raii_guard` | still failing — `:86` |

Build these with `arm-linux-gnueabihf-g++` and `g++`, not `gcc`; the fixture is
`10_cpp_runtime_shapes.cpp`.

**Root cause found and fixed: ARM32 pointer PARAMETERS were typed `int`.**

`static int consume(Movable m)` recovered as `int consume(int arg0)` on armv7
and `int consume(int *arg0)` on x86-64 — from a body that plainly dereferences
the parameter in both. The caller then reads
`_ZL7consume7Movable((int)(&local_28[0] + 20))`: a pointer cast to `int`.

This is invisible on a 32-bit target, where a pointer and an `int` are both four
bytes — and lethal once the recovered C is rebuilt at 64 bits, because the
caller truncates a real pointer to 32 bits before the call. Note the audit
classified it REAL and was right to: the recovered C names no width-varying
type. `int` is 32 bits on both sides. The *defect* is that a pointer was spelled
`int` at all.

The chain: at -O0 ARM spills the pointer argument to a frame slot and every
later dereference goes through a reload, so the pointer classification lands on
the reloaded temp, never on the incoming `r0`. `propagate_spill_slot_pointers`
exists to walk that back — but it is gated on `is_frame_base`, which read:

```rust
matches!(n.as_str(), "rbp" | "rsp" | "ebp" | "esp" | "x29" | "sp" | "w29")
```

x86-64, 32-bit x86 and AArch64 — and **not ARM32**, whose frame pointer is `r7`
under Thumb and `r11` under A32. So `store [r7+4] = r0` was not a spill to
anything and the propagation had nothing to walk.

A second, independent bug in the same line: it compared whole names. x86-64
writes `rbp` once so it never gets an SSA suffix and a bare `"rbp"` match worked
by luck; ARM saves the incoming `r7` and defines a new one, so its frame base is
spelled `r7#1`. Both halves had to be fixed. Pinned by
`frame_bases_cover_arm32_and_ignore_the_ssa_suffix` in `src/ir/types_recover.rs`.

The remaining three are **not diagnosed**. Their bodies now read as
semantically correct against the source, and their signatures match x86-64's, so
whatever is wrong is subtler than the above. One benign difference to *not*
chase: ARM declares the ctors returning `char *` where x86-64 says `void`. That
is correct — AAPCS returns `this` in `r0` — and is invisible at link time.

---

### `03_loop_shapes:O0:dowhile_atleastonce` — DIAGNOSED, not fixed

The recovered index is wrong in a way that is *faithful to the machine code*:

```c
arg0[((*(int *)((&local_18[0] + 8)) + 0x40000000) - 1)]   /* source: p[i - 1] */
```

`0x40000000` is not an artefact — it is in the binary:

```text
 79a:  ldr   r3, [r7, #8]              ; i
 79c:  add.w r3, r3, #1073741824       ; i + 0x40000000
 7a0:  subs  r3, #1
 7a2:  lsls  r3, r3, #2                ; <<2 -- 0x40000000 shifts clean out
```

gcc adds 2^30 knowing it vanishes: `(i + 2^30 - 1) * 4 == (i - 1) * 4 (mod 2^32)`.
The recovery is correct at 32 bits and wrong everywhere else — rebuilt at host
width the term does not truncate, so `arg0[huge]` runs off the array. That is the
execution failure, and it is why the audit calls this REAL: the recovered C names
no width-varying type, so the host rebuild genuinely is the 32-bit semantics.

Note x86-64 does not hit this. It leaves the byte arithmetic alone
(`*(int *)((long)arg0 + ((local_8 << 2) - 4))`) rather than recovering an index,
so there is nothing to mis-scale.

**The fix is a provable modular simplification**: in a width-`W` computation,
`(x + C) << s == x << s` whenever `C * 2^s ≡ 0 (mod 2^W)`. For `C = 0x40000000`,
`s = 2`, `W = 32` that holds exactly.

**Why it was not just added to `const_fold`.** The identity is only true at the
width the machine actually computes at, and `fold_constants(f: &mut Function)`
has neither an architecture nor a width — at `W = 64` the same rewrite is plain
wrong, because `0x40000000 << 2` is a perfectly good 64-bit value. Folding it
unconditionally would introduce precisely the silent-wrong-answer defect this
document is otherwise a catalogue of. `fold_typed_comparison_extensions(f, tm)`
shows the shape a safe version would take — a width-aware fold entry that
consults the `TypeMap` — and that is where this belongs.

## Cluster D — pointer/array-heavy algorithms (16 defects) — **1 of 16 DIAGNOSED**

| fixture | opt | function | source |
|---|---|---|---|
| `03_loop_shapes` | O0 | `dowhile_atleastonce` | `int dowhile_atleastonce(const int *p)` — `:110` |
| `04_switch_shapes` | O2 | `negative_cases` | `int negative_cases(int x)` — `:80` |
| `04_switch_shapes` | O2 | `sparse_shared_tail` | `int sparse_shared_tail(int x)` — `:259` |
| `07_packet_parser` | O0 | `parse_packet` | `int parse_packet(const uint8_t *buf, int len)` — `:143` |
| `13_loop_early_exit` | O0 | `classify_run` | `int classify_run(const int *a, int n)` — `:77` |
| `15_binary_search_tree` | O2 | `bst_inorder_checksum` | `bst_inorder_checksum(const BstNode *nodes, int32_t n, int32_t root)` — `:31` |
| `18_binary_heap` | O0 | `heap_pop` | `int32_t heap_pop(int32_t *heap, int32_t n, ...)` — `:25` |
| `18_binary_heap` | O2 | `heap_pop` | " |
| `20_graph_bfs` | O2 | `graph_bfs` | `int32_t graph_bfs(const int32_t *adjacency, int32_t n, ...)` — `:3` |
| `21_graph_dfs` | O2 | `graph_dfs` | `int32_t graph_dfs(const int32_t *adjacency, int32_t n, ...)` — `:3` |
| `22_dijkstra` | O0 | `dijkstra_dense` | `int32_t dijkstra_dense(const int32_t *weights, ...)` — `:4` |
| `22_dijkstra` | O2 | `dijkstra_dense` | " |
| `23_topological_sort` | O2 | `topological_sort` | `int32_t topological_sort(const int32_t *adjacency, ...)` — `:3` |
| `25_kmp_search` | O2 | `kmp_search` | `int32_t kmp_search(const uint8_t *text, int32_t n, ...)` — `:3` |
| `30_finite_difference` | O0 | `heat_step_1d` | `uint32_t heat_step_1d(int32_t *destination, ...)` — `:3` |
| `30_finite_difference` | O2 | `heat_step_1d` | " |

**Evidence: verdicts only. No recovered C inspected, no root cause proposed.**
"Pointer/array-heavy" is a description of the fixtures, not a claim about the
cause. These are grouped because they are what is left, and because grouping
them keeps the honest clusters honest.

Three observations that are *cheap to act on* and are offered as leads, not
conclusions:

- `heap_pop`, `dijkstra_dense` and `heat_step_1d` fail at **both** O0 and O2.
  Cross-opt failures usually indicate a lifting or model defect rather than a
  structuring one, and they are the better starting point for that reason.
- The `20/21/22/23/25` group is O2-only and all take `const int32_t *` plus a
  count. If Cluster A's flag-write defect turns out to affect loop guards, some
  of these should fall out with it — which makes **fixing Cluster A first and
  re-running this list** the cheapest possible triage step for the other 24.
- These are the largest fixtures on the page. Diagnose the small ones first;
  a `dijkstra_dense` diff is not where anyone should start.

---

## Known and NOT fixed: ARM32 stack frames do not promote

Found while diagnosing Cluster C, confirmed to the line, and left alone on
purpose. It is the single highest-leverage item remaining, and it is a design
change rather than a list edit.

`src/ir/stack_locals.rs:31`:

```rust
const STACK_BASES:         &[&str] = &["rsp","esp","sp","rbp","ebp","bp","x29","w29","fp"];
const FRAME_POINTER_BASES: &[&str] = &["rbp","ebp","bp","x29","w29","fp"];
```

ARM32's `r7`/`r11` are absent, exactly as in `is_frame_base`. The consequence is
visible in every armv7 -O0 function: the frame never splits into named locals
the way x86-64's does, and stays one opaque byte array —

```c
unsigned char local_20[32];
long lr;
long var0;
*(int *)((&local_20[0] + 24)) = var0;   /* saved r7  */
*(int *)((&local_20[0] + 28)) = lr;     /* saved lr  */
```

— where x86-64 gets `local_8`, `local_1c` and so on. Two knock-on effects:

1. **Every ARM32 function reads `lr` and the saved `r7` undefined.**
   `dead_stores::prune_callee_saved_spills` matches a spill as
   `Stmt::Store { addr: Expr::Reg(slot), .. }`, i.e. a *promoted* slot. ARM's
   spill is `store (&local_20 + 24) = %r7` — an offset into an array — so it
   matches nothing and the callee-save idiom is never elided. This is why `lr`
   appears as an undefined local in essentially all armv7 output.
2. Anything keyed on named stack locals is weaker on ARM32 than elsewhere.

**Why this is not a one-line fix, and the trap to avoid.** The sign convention
is architecture-dependent. `stack_locals.rs:2269` treats
`is_frame_pointer(base) && disp < 0` as a frame local and `:2301` treats
`disp > 0` as the incoming-argument area — correct for x86, where `rbp` sits
above the locals. ARM's prologue is `add r7, sp, #0`, so `r7` points at the
**bottom** of the frame and its locals are at **positive** displacements.
Adding `r7`/`r11` to `FRAME_POINTER_BASES` without also making the direction
architecture-dependent would classify every ARM local as an incoming stack
argument — a much worse failure than the present one, and one the `x86_64`
control lane cannot catch.

So this needs `FRAME_POINTER_BASES` to become a per-architecture descriptor
carrying *(name, direction)*, not a flat name list. That is EPIC 4's actual
content. Do it deliberately, with `--check` after each step.

### The attempt that was made, and what it proved

Registering `r7`/`r11` as stack bases (gated on the prologue actually
establishing them from `sp`, so `-O2`'s general-purpose `r7` was excluded) was
tried and **reverted**: armv7 went 82.0% -> 76.2%, 15 regressions, 0
improvements. The failures name the cause exactly —
`06_calling_conventions:O0:sum_arg5` through `sum_arg10`, i.e. every function
with incoming *stack* arguments. Those arguments are at positive displacement
from `r7` too, just further up, so without a frame-extent boundary they are
indistinguishable from locals and each one got minted as a second, differently-
named slot. The recovered frame did split into named locals, and `consume`'s
body came out clean — the promotion half works. Only the boundary is missing.

### The sign convention differs between Thumb and A32 — verify, do not assume

A hypothesis was raised here that `fp` (ARM's `r11`) carried the same
positive-displacement convention as `r7`, and that its presence in
`FRAME_POINTER_BASES` was therefore a latent bug putting A32 locals through
`stack_arg_layout`. **That was wrong, and disassembling an A32 build disproved
it.** Recorded because the mistake is easy to repeat.

The two ARM frame registers differ, and the difference is *when* the frame
pointer is established relative to the `sub sp`:

```text
Thumb (r7)                       A32 (r11/fp)
  push  {r7, lr}                   push  {fp}
  sub   sp, #N                     add   fp, sp, #0     <- BEFORE the sub
  add   r7, sp, #0   <- AFTER      sub   sp, sp, #20
  str   r0, [r7, #4]  positive     str   r0, [fp, #-8]   negative
```

So A32's `r11` behaves exactly like x86's `rbp` — frame pointer above the
locals, locals at negative displacement — and its listing in
`FRAME_POINTER_BASES` is **correct**. Only Thumb's `r7` inverts the direction,
which is precisely why `r7` cannot simply be added to that list.

Removing `fp` from the two lists was tried and reverted: it changed no verdict
(the armv7 lane is `-mthumb`, so `r11` is never the frame pointer there and the
corpus cannot see the difference either way), and it would have mis-modelled A32
in a way nothing in this harness tests. If ARM32 frame handling is reworked,
**add an A32 (`-marm`) lane first** — there is currently no coverage of it at
all, and every claim about `r11` is therefore unfalsifiable by the gate.

### A third ARM32 register-list bug, fixed but UNEXERCISED

`python_bindings/ir.rs` mapped DWARF stack-object bases for ARM as:

```rust
(CallConv::Arm | CallConv::ArmHardFloat, DwarfStackBase::Register(11 | 7)) => ("fp", 0),
```

ARM DWARF numbers `r0`..`r15` as 0..15, so register 7 is `r7` and register 11 is
`r11` — different registers, and AAPCS uses each as the frame pointer in a
different instruction set. The disassembler spells them `r7` and `fp`, so
collapsing both to `"fp"` gave a Thumb function's aggregate a base register it
does not address its frame through. Now mapped separately.

**Stated plainly: this changed no verdict and no recovered output on the
corpus.** `20_graph_bfs` (which has `int32_t queue[16]` and `uint8_t seen[16]`)
recovers byte-identically before and after, so its blobs come from address-taken
analysis rather than these hints. The change is kept because it is a *factual*
register-number-to-name correction, not a theory about calling convention — the
distinction that separates it from the reverted `fp` experiment above — but it
is not evidence-backed and should not be cited as a fix for anything.

### ARM aggregates get no DWARF extent at all — and the blocker is the same one

Investigated from that starting point, and it converges on the frame-promotion
item above. ARM has no `DwarfStackBase::CallFrameCfa` arm where x86-64, i386 and
AArch64 all do, and this is the *common* path rather than a corner:

```text
ARM :  DW_AT_frame_base : DW_OP_call_frame_cfa      <- and every local is DW_OP_fbreg
x86 :  DW_AT_frame_base : DW_OP_call_frame_cfa
ARM :  queue -> DW_AT_location: DW_OP_fbreg -92
```

So *every* ARM aggregate hint is dropped, and `graph_bfs`'s `int32_t queue[16]`
has no recovered extent on armv7 while x86-64 recovers it as `local_60[64]`.

Adding a match arm does not fix it, and that was verified rather than assumed.
AAPCS pushes no return address (it is in `lr`), so the CFA is the entry stack
pointer itself rather than a fixed distance from a frame register the way
x86-64's `rbp + 16` is — the natural base is `entry_sp`. But
`stack_locals::promote_*` filters every hint through `is_active_stack_base`, and
neither `entry_sp` nor ARM's `r7` is in `STACK_BASES`, so the hint is rejected at
intake. Emitting `("entry_sp", 0)` was tried and changed `graph_bfs`'s recovery
not at all; the arm was removed again rather than left in as dead code with a
confident comment.

**This is the same blocker as ARM frame promotion**: the hint vocabulary and the
slot vocabulary both need to admit the entry anchor. One coordinate-system change
unlocks both, which raises the value of doing it properly.

## What is deliberately NOT in this document

**The 28 UNSEPARABLE armv7 failures.** Their recovered C names a type whose size
changes between ILP32 and LP64, so executing it at host width cannot distinguish
a real defect from a portability artifact. They are *not* known-good and *not*
known-bad. Closing that gap needs the differential worker to execute at 32 bits
— currently impossible because the worker is 64-bit CPython driving
`ctypes.CDLL`, which refuses a 32-bit object outright (`wrong ELF class:
ELFCLASS32`). See the header of `tools/arch_roundtrip.py` for why a hand-rolled
replacement comparator is a trap.

**The 54 `aarch64` failures.** All real (64-bit, no width confound, zero
ABI-incomparable), and probably the higher-value pile — but out of scope here.

**The 14 real `i386` defects.** Same audit, different lane.

**Anything about `byte_match` numbers.** The metric fix described at the top of
this document lives in the DecBench checkout at
`/nas4/data/workspace-infosec/decbench` (uncommitted, on top of `efc5d5a`, with
regression tests in `tests/test_arm_thumb_extraction.py`). It corrects
submission-side scoring and is worth upstreaming, but it is **not** on the
critical path for any defect on this page, and no fix here should be validated
against it.

---

## Suggested order of attack (updated)

1. **ARM32 stack-frame promotion**, above. Highest leverage left: it removes the
   undefined `lr`/`r7` reads from *every* armv7 function and strengthens every
   pass keyed on named locals. Needs the per-architecture direction descriptor;
   do not shortcut it with a name-list edit.
2. **`O2:tail_dispatch`** — a well-understood shape (tail call through a
   resolved function table, plus unrecovered argument setup) with the table
   half already working.
3. **Cluster D**, smallest fixture first, cross-opt failures
   (`heap_pop`, `dijkstra_dense`, `heat_step_1d`) before O2-only ones. Still
   undiagnosed; do not trust the cluster heading as a cause.
4. **The three remaining C++ shapes**, which are now the subtlest of the set —
   their bodies read correctly and their signatures match the control.

Two process rules earned the hard way this session:

- **Re-run `--width-audit` after every fix, before diagnosing anything else.**
  One fix took the REAL list from 26 to 20; diagnosing a defect that a pending
  fix would have deleted is wasted work.
- **Run the full `--check`, not the fixture you are working on.** The Cluster A
  fix looked right in the recovered C of its own fixture and silently broke
  `05_cleanup_and_state_machine:O2:fsm`. Only the ratchet saw it.

Re-run `python3 tools/arch_roundtrip.py --check --jobs 8` after each change. The
`x86_64` control must stay at 100.0%; if a fix moves it, the fix is wrong no
matter what it did to armv7.
