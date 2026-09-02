# Decompiler parity: what a three-way comparison found, and what to build

> **Kind:** guide · **Status:** maintained

A head-to-head of glaurung against **angr 9.3.3** and **Ghidra 12.1.3** on our
own clang sample binaries, scored against the real C source, plus the
prioritized backlog that falls out of it.

Written 2026-08-31. The comparison is small by design — two binaries, a
handful of functions — so it is a *diagnostic*, not a benchmark: enough to
show **where** the gap is, not to score it. The corpus-scale number stays
DecBench (held out), where our O0 result still trails angr; this document
explains what that number is made of.

## The one-line finding

On these samples glaurung **leads on types and semantic fidelity** and
**trails on readability and naming**. That is the whole story, and it is
actionable: the gap is not "our analysis is wrong," it is "our output reads
like lifted IR where theirs reads like source."

## Reproducing it

Both reference tools are installed on this box.

* **angr**: `uv pip install angr` (9.3.3). Decompile one function:

  ```python
  import angr
  proj = angr.Project(binpath, auto_load_libs=False)
  cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
  func = next(f for f in cfg.kb.functions.values() if f.name == name)
  proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model)
  print(proj.analyses.Decompiler(func, cfg=cfg.model).codegen.text)
  ```

* **Ghidra**: 12.1.3 at `/opt/ghidra` (→ `/opt/ghidra_12.1.3_PUBLIC`),
  needing **JDK 21** (`/usr/lib/jvm/java-21-openjdk-amd64`; JDK 25 is too new,
  17 too old for 12.x). Headless:

  ```bash
  export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
  /opt/ghidra/support/analyzeHeadless <PROJ_DIR> <name> \
    -import <binary> -overwrite \
    -scriptPath <SCRIPT_DIR> -postScript DecompFn.java main print_sum ...
  ```

  **Gotcha that cost real time:** `analyzeHeadless` rejects any project or
  script path containing a **dot-prefixed element** ("Path element starting
  with '.' is not permitted") — so it cannot live under `~/.cache/...`. Use a
  dotless dir like `~/glaurung-ghidra/`. The `DecompFn.java` postscript is a
  `GhidraScript` that opens a `DecompInterface` and prints
  `getDecompiledFunction().getC()` for each named function.

* **glaurung**: `uv run glaurung decompile <bin> --func <name> --style
  decbench --no-color`. **Use `--style decbench`, not `--style c`** — the `c`
  style is the low-level IR view (exposes `%sf`/`%of` flag math); `decbench`
  is what we actually score and the only fair thing to compare.

All of the above is now one command -- `uv run python tools/compare_decompilers.py
<binary> main print_sum` -- which is backlog item #7, landed. The manual recipe
is kept here because it is what the tool automates, and because a reader
debugging the tool needs it.

## The evidence

### hello-c `main`, clang -O0 — argv typing

Source: `int main(int argc, char **argv)`, `sum += strlen(argv[i])`.

```c
// glaurung
int main(int arg0, long *arg1) {
    for (local_18 = 0; (local_18 < arg0); local_18++) {
        var8 = strlen((const char *)(arg1[(long)(local_18)]));   //  arg1[i]
        ...
// angr
unsigned int main(int a0, unsigned long a1) {
    for (i = 0; i < a0; i += 1)
        v1 += (unsigned int)strlen(*((long long *)(a1 + i * 8)));  //  manual
// Ghidra
undefined8 main(int param_1, long param_2) {
    for (local_20 = 0; local_20 < param_1; ...)
        sVar1 = strlen(*(char **)(param_2 + (long)local_20 * 8));  //  manual
```

glaurung is the **only** one that recovers the array parameter and indexes it
as `arg1[i]`; both others flatten to `*(T*)(p + i*8)` arithmetic. (We render
the element as `long *` where it should be `char **` — backlog #6.)

### suspicious_linux `main`, clang -O0 — the page-align idiom

Source: `mprotect((void*)((unsigned long)main & ~0xFFF), 4096,
PROT_READ|PROT_EXEC)` — code page-aligning its own address, the whole point
of the "suspicious" sample.

```c
// glaurung  ✅
local_20 = ((long)(main) & -4096);
var11 = mprotect(local_20, 4096, 5);
// angr      ❌  snapped to a symbol, mask dropped
v2 = _init;
mprotect(v2, 0x1000, 5);
// Ghidra    ❌  same error
local_28 = _init;
mprotect(_init, 0x1000, 5);
```

glaurung is the **only** tool that preserves `main & ~0xFFF`. angr and Ghidra
both resolve the runtime-computed page base to the `_init` symbol that happens
to sit at 0x1000 and drop the masking entirely. For triage that is exactly the
signal you do not want erased. → backlog #9.

### static counter — DWARF name vs synthetic global

```c
// Ghidra    ✅ real DWARF name
static_function_static_var = static_function_static_var + 1;
// glaurung  ❌ synthetic
*(int *)(&glaurung_global_4040[0]) = ... + 1;
// angr      ❌ wrong borrowed symbol
__TMC_END__ = __TMC_END__ + 1;
```

**Correction, found while implementing this.** The first version of this
section said Ghidra was ingesting the DWARF name. It was not: these binaries
have **no `.debug_*` sections at all**. The name is an ELF **symbol table**
entry -- `static_function.static_var`, an `OBJECT` symbol at `0x4040`, which is
exactly the address our synthetic name encoded. That correction is what made
the fix small, and it also widens where it applies: an unstripped symbol table
is far more common than shipped DWARF. → backlog #1, **landed**.

### O2 loop guard — condition simplification

```c
// Ghidra:    if ((int)param_1 < 1) { ... } else { do {...} while (param_1 != uVar2); }
// angr:      if (a0 > 0) { ... } else { ... }
// glaurung:  if (((...==0) | ((int)(var1) < 0))) { ... } else { ... }
```

Functionally `x <= 0`, but we render the raw OR of the two flag comparisons
the compiler emitted; both others fold it. This is the biggest readability
gap. → backlog #2.

### The correction — O2 dropped `printf` argument

At O2 `static_function` inlines into `main` and the second `printf` loses its
argument:

```c
// glaurung O2:  printf("Static function called %d times\n");            // no arg
// Ghidra  O2:   printf("Static function called %d times\n");            // no arg  ← identical
// angr    O2:   printf("Static function called %d times\n", __TMC_END__); // kept, wrong name
```

An earlier note called this "a glaurung bug." **Ghidra makes the identical
error**, so it is a hard shared limitation of threading a register value
through an inlined increment, not a unique defect — but angr proves it is
solvable. → backlog #4.

## The backlog

Ordered by impact-per-effort. `fix` = correct existing behaviour; `build` =
new capability. Effort L/M/H is a rough half-day / few-days / week+.

### Correctness & score cluster (closes the gap the comparison exposed)

1. **~~Ingest DWARF local/static variable *names*.~~ LANDED** (`dfd2ddb4`)
   as **symbol-table** ingestion, not DWARF -- see the correction above.
   `src/ir/data_symbols.rs` maps an exact start address to a sized `OBJECT`
   symbol; `dec_global_name` consults it. Output for the motivating case is
   now `static_function_static_var`, matching Ghidra. The match is
   exact-start-only, which is what stops us reproducing the `_init` error in
   the next entry; `no_nearest_symbol_fallback` is that guard as a test.

2. **~~Simplify comparison guards before render.~~ LANDED** (`96948a4b`)
   as `src/ir/cmp_fusion.rs`. The eleven-token disjunction is now
   `if (((long)((int)(var1)) <= 0))`, which is what Ghidra prints, cast and
   all.

   **Worth recording how it went wrong first.** The initial version matched
   the two sides by peeling casts and rebuilt the result from the peeled
   value, which silently changed the comparison's width -- for 64-bit `v`
   holding 2^32, `v == 0` and `(int)v < 0` are both false but `(int)v <= 0` is
   true. Eleven execution-differential lanes went red and caught it. The pass
   now requires equal observed widths and reuses the signed operand verbatim.
   The lesson generalises: a "readability" transform is a semantic transform,
   and the fixture matrix is the thing that knows.

3. **Recover variadic / call-site argument arity.** `fix` · effort **M–H** ·
   evidence: `ptrace(0)` (one arg) vs the real four. Needs call-site
   argument-register liveness, not just the callee prototype. Moves
   `type_match` and the def-use census directly.

4. **Thread register values across inlined bodies.** `fix` · effort **L** ·
   evidence: O2 dropped-arg. Add the fixture first (it is a clean, minimal
   reproduction), then fix the dataflow that loses the inlined static-var
   read. Target: match angr (arg present) with the correct name (which #1
   gives us) — i.e. beat both reference tools on this case.

   > **Located 2026-09-01, and the title is wrong.** Inlining is not the
   > cause, and neither is variadic arity. Two minimal candidates were built
   > and *neither reproduced*:
   >
   > * a static counter inlined into a caller, feeding a `noinline` sink —
   >   both call arguments recovered correctly;
   > * the same with a **variadic** callee in the caller — all four arguments
   >   recovered, `__printf_chk(2, "b=%d b2=%d\n", var6, var2+var6)`.
   >
   > What reproduces, on **both** gcc and clang, is 12 lines — the `printf`
   > must be *inside* the function that gets inlined:
   >
   > ```c
   > static void inlined_printf_arg(void) {
   >   static int static_var = 0;
   >   static_var++;
   >   printf("called %d times\n", static_var);
   > }
   > int driver(int n) {
   >   inlined_printf_arg();
   >   if (n > 1) inlined_printf_arg();
   >   return n;
   > }
   > ```
   >
   > **The discriminator is an intervening read, not inlining.** Compare the
   > argument register's defining instruction in the two cases:
   >
   > ```asm
   > ; works:  edx defined by a register move, nothing reads it before the call
   >   mov  %r12d,%edx
   >   mov  %ebx,counter(%rip)
   >   call __printf_chk
   >
   > ; drops:  edx defined by lea, then READ by the store to the static
   >   lea  0x1(%rax),%edx
   >   mov  %edx,static_var(%rip)      <-- reads edx
   >   call __printf_chk
   > ```
   >
   > `call_args.rs`'s module contract requires that the argument register "is
   > not read between the assignment and the call". The store reads `edx`, so
   > the fold is refused and `blocked_incoming[slot] = true` — the argument is
   > dropped entirely.
   >
   > **The conflation is the bug.** `read_between` answers *can this
   > definition be moved into the call?*, and it is being used to answer *is
   > this slot an argument at all?* Those are different questions. A read does
   > not disturb the register: at the call it still holds the same value.
   >
   > `fold_one_call.rs` **already has the correct handling** and gates it too
   > narrowly:
   >
   > ```rust
   > if read_between[slot]
   >     && (proven_aapcs_stack
   >         || (arch == CallConv::Aarch64 && later_slot_proves_contiguous_prefix))
   > {
   >     // "An intervening read means its definition cannot be deleted, so
   >     //  keep the statement rooted and pass the exact reaching SSA value."
   >     found[slot] = Some((KEEP_ARG_SETUP, Expr::Reg(dst.clone())));
   > ```
   >
   > On x86-64 SysV neither guard can hold, so the slot is blocked instead.
   > Because the backward scan takes the *closest* definition of the slot,
   > nothing writes the register between that definition and the call — so
   > naming the register is sound there for the same reason it is sound under
   > AArch64.
   >
   > **Why it is not simply relaxed here.** Widening the gate makes every
   > SysV call with an intervening read claim the slot, which can invent
   > arguments on calls that never had them. That is a corpus-wide trade, and
   > it is exactly what the readability census and the def-use census exist to
   > weigh — the same discipline that reverted `detect_raw_dispatch_loop`
   > (`test-estate/10-ci-environment-gap.md`). Measure before landing.
   >
   > Ghidra makes the identical error on the real sample; angr keeps the
   > argument. Ranking unchanged, but the effort is now known to be a
   > one-condition change plus a corpus measurement, not dataflow work.
   >
   > ### Both candidate fixes were built and measured. Neither lands.
   >
   > **The principled one does not reach the case.** The contiguity guard is
   > restricted to AArch64, and "argument registers form a contiguous prefix"
   > is an ABI fact that holds for SysV and Win64 too, so widening it looked
   > like the correct minimal change. It is inert here: contiguity proves a
   > slot is an input only from a *higher* occupied slot, and in this shape
   > `rdx` is the highest one set. Built, and the argument is still dropped.
   >
   > **The broad one works and costs far too much.** Keeping the slot rooted
   > whenever a read intervenes recovers the argument on the minimal case and
   > on the real binary:
   >
   > ```c
   > printf("Static function called %d times\n", var17)   // beats Ghidra, and
   >                                                      // angr's __TMC_END__
   > ```
   >
   > The execution differential *endorsed* it -- 824 host lanes, **2
   > improvements, zero regressions**, `132_cpp_vtable_layout` and
   > `139_cpp_object_lifetime` going fail -> pass. The def-use census did not:
   >
   > | lane | undefined reads | unverified functions |
   > |---|---|---|
   > | clang:O0 | 140 -> **552** | 36 -> 242 |
   > | clang:O2 | 256 -> **668** | 86 -> 292 |
   > | gcc:O0 | 124 -> **536** | 20 -> 226 |
   > | gcc:O2 | 136 -> **548** | 65 -> 271 |
   > | rustc:O0 | 7658 -> 7764 | |
   >
   > About 1,600 new undefined reads across the host lanes -- roughly 4x --
   > plus two brand-new violations in Rust fixtures. That is the invented-
   > argument failure mode stated as a number: the gate is claiming slots that
   > were never arguments, and the emitted call then reads a register nothing
   > defined. Reverted; `fold_one_call.rs` is byte-restored and the census is
   > green.
   >
   > ### What a landing fix needs
   >
   > Independent evidence that the slot **is** an argument, which
   > `read_between` cannot supply because it answers a different question
   > (*may this definition be moved?*). The contiguity rule is one such
   > evidence source and is simply absent in this shape. The other, and the
   > one that fits every motivating case here, is **format-string arity**:
   > `"called %d times\n"` has one conversion, so `__printf_chk` takes
   > exactly three arguments. `call_contracts.rs` already carries
   > `is_variadic` and deliberately declines to cap variadic calls
   > (`fixed_scalar_argument_registers` returns `None` for them); nothing
   > parses format strings. That makes this item a dependent of #3 rather than
   > an independent one-condition change -- **re-rank it below #3**, and note
   > that #3 buys #4 for free once printf-family arity is derivable.
   >
   > Second time in this session that the execution differential blessed a
   > change a census rejected (the other:
   > `test-estate/10-ci-environment-gap.md`). Correctness gates and quality
   > gates are answering different questions, and a change touching argument
   > recovery must clear both.

### Triage value & polish

5. **~~Named constants for syscall/flag arguments.~~ LANDED** as
   `src/ir/named_constants.rs`. Output is now
   `ptrace(0 /* PTRACE_TRACEME */)` and
   `mprotect(local_20, 4096, 5 /* PROT_READ|PROT_EXEC */)`.

   A **comment**, not a substitution, and that is the whole design decision:
   this render is recompiled by the execution differential, so a bare
   `PROT_READ` would need headers the renderer does not emit and would trade
   readable output for output that does not build. On this call we are now
   ahead of both reference tools -- Ghidra names the `ptrace` request but
   still reports `mprotect(_init, 0x1000, 5)`.

6. **Render pointer/array types in their real C form.** `fix` · effort **M-H**,
   **re-scoped after reading the code** · evidence: we recover the array but
   print `long *arg1` where it is `char **argv`.

   This was written down as effort **L**, "polish on an existing strength".
   It is not. `TypeHint::Pointer { pointee_width: u8 }`
   (`src/ir/types_recover.rs:61`) is **width-only and not recursive**: the
   model can say "pointer to eight bytes" and cannot say "pointer to pointer
   to char" at all. So there are two different jobs hiding under one line:

   * **The cheap one (M).** The evidence is already at the use site -- we
     emit `strlen((const char *)(arg1[i]))`, so the load's destination type
     is known there. A renderer-level rule could declare the parameter
     `char **` when every load through it flows into a `T *` callee
     parameter, without touching `TypeHint`. Narrow, and it fixes the
     motivating case.
   * **The real one (H).** Making the type model carry a recursive pointee
     so any depth of indirection is expressible. That is a change to a
     structure most of `types_recover/` reads.

   Do the first, and do not let it be mistaken for the second.

### Measurement & lock-in (keeps the other eight honest)

7. **~~`tools/compare_decompilers.py`~~ LANDED** (`dfd2ddb4`). One command,
   both reference tools optional, JSON or side-by-side text. It carries the
   two Ghidra gotchas so nobody pays for them twice: `analyzeHeadless` rejects
   any path with a dot-prefixed element (so its project cannot live under
   `~/.cache`), and Ghidra 12.x needs JDK 21 specifically -- 17 is too old and
   25 is rejected.

8. **Extend the structural baseline to O2.** `build` · effort **M** · the
   comparison *showed* angr/Ghidra structuring cleaner, but no glaurung gate
   scores structuring at O2 (baseline is gcc-O0 only; the execution
   differential is blind to goto-soup). This is Phase 7.5 of
   [`test-estate/07-matrix-extension.md`](test-estate/07-matrix-extension.md);
   the comparison is what makes it urgent.

9. **Page-align fixture + symbol-snapping guard.** `build` · effort **L**
   (fixture) **+ M** (guard) · evidence: mprotect case. Lock in the win where
   we are the only correct tool, and add the correctness guard it generalizes
   to: never rewrite a *runtime-computed* address as a static symbol
   reference. That guard is also what keeps us from regressing *into* the
   angr/Ghidra error.

10. **Wire angr/Ghidra as documented optional dev oracles.** `build` · effort
    **L** · pin the versions (angr 9.3.3, Ghidra 12.1.3, JDK 21), record the
    headless invocation and the dotless-path gotcha (this file is the first
    draft of that), and make them an opt-in dev dependency behind a flag so
    #1 and #7 have trusted reference output on demand.

## If you build in one order

`1 → 2 → 4` first: DWARF names, condition simplification, the inlined arg —
the three that most directly convert "reads like IR" into "reads like source."
Stand up `7` early so each of those is verifiable against the reference the
day it lands. `3, 5, 6` are independent and parallelizable. `8, 9, 10` are the
scaffolding and lock-in.

## Scope and honesty

Two binaries, unstripped, x86-64, clang only. Ghidra's DWARF-name advantage
(#1) is real here but would not apply to stripped malware — though the
*mechanism* (use debug info when present) is still correct to build. None of
this reads or tunes against DecBench or `tests/decbench_corpus/`. The
reference outputs quoted above were captured on the versions named and will
drift; #7 exists so the comparison can be re-run rather than trusted.
