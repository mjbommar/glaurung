# Decompiler parity: what a three-way comparison found, and what to build

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

Item #7 of the backlog is to turn this into `tools/compare_decompilers.py` so
it is one command instead of the above.

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

The binaries are unstripped; Ghidra ingests the DWARF *name*, we do not (though
we do ingest DWARF for *function* names). → backlog #1.

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

1. **Ingest DWARF local/static variable *names*.** `fix` · effort **M** ·
   evidence: static-counter case above. We parse DWARF for function names
   already; the local/static name is in the same DIE tree and is not wired
   into recovered globals/locals. Highest value-to-effort here — the data is
   already parsed. Verify with the unstripped samples where the expected name
   is known.

2. **Simplify comparison guards before render.** `fix` · effort **M** ·
   evidence: O2 loop guard. A peephole recognizing the `(eq ∨ signed-lt)` →
   `le` (and siblings) flag idioms, applied to the rendered condition. Most
   likely single driver of our DecBench GED/byte-match deficit, because it
   changes the shape of nearly every non-trivial branch.

3. **Recover variadic / call-site argument arity.** `fix` · effort **M–H** ·
   evidence: `ptrace(0)` (one arg) vs the real four. Needs call-site
   argument-register liveness, not just the callee prototype. Moves
   `type_match` and the def-use census directly.

4. **Thread register values across inlined bodies.** `fix` · effort **L** ·
   evidence: O2 dropped-arg. Add the fixture first (it is a clean, minimal
   reproduction), then fix the dataflow that loses the inlined static-var
   read. Target: match angr (arg present) with the correct name (which #1
   gives us) — i.e. beat both reference tools on this case.

### Triage value & polish

5. **Named constants for syscall/flag arguments.** `build` · effort **M** ·
   evidence: Ghidra's `ptrace(PTRACE_TRACEME,...)`; our `mprotect(...,5)`
   should read `PROT_READ|PROT_EXEC`. A curated table keyed by (function,
   arg-position); no analysis change, high analyst value.

6. **Render pointer/array types in their real C form.** `fix` · effort **L** ·
   evidence: we recover the array but print `long *arg1` where it is
   `char **argv`. Polish on an existing strength (#argv case).

### Measurement & lock-in (keeps the other eight honest)

7. **`tools/compare_decompilers.py` — a reproducible differential harness.**
   `build` · effort **M** · wrap the angr + Ghidra invocations above so
   "where do we diverge from the reference" is one command. Depends on the
   installed oracles (#10). This is what makes 1–6 measurable rather than
   anecdotal.

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
