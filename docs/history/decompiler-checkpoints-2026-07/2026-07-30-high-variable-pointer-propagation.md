# High-variable pointer propagation checkpoint

> **Kind:** record · **Date:** 2026-07-30

Date: 2026-07-30

## Verdict

Glaurung now preserves pointer types across exact prepared-AST value identities
(`varN`) instead of stopping at the original LLIR producer. On the blinded
DecBench sample this raises official snippet/fixup compilability from **123/250
to 127/250**, with **four gains and zero losses**.

This is a bounded type-recovery improvement, not a claim that Glaurung is yet
competitive with Ghidra or angr overall. The retained whole-sample results still
show a substantial GED and type-recovery gap. The architectural value of this
slice is that later type facts can now follow a stable source value instead of a
reused physical register name.

## Root cause

The existing type pass runs on raw LLIR, before SSA-derived values receive their
final source names. Call contracts and literals therefore identified pointer
producers correctly, but a final copy such as

```text
call getenv -> rax.4
var1 = rax.4
local_8 = var1
return local_8
```

lost the pointer fact at `var1`. The renderer deliberately declared every
`varN` as `long`, so the generated C failed at ordinary C pointer boundaries.

The unsafe shortcut would be to trust any old `TypeMap` fact whose spelling
happened to be `varN`. That map was keyed by reusable machine storage, not the
prepared AST's exact value identity. The new pass first clears those collisions
and then proves facts again from the prepared definition graph.

## Reference design comparison

The implementation follows the same boundary used by the reference
decompilers, at a smaller current scope:

- Ghidra's high-level IR groups Varnodes into HighVariables, propagates through
  COPY-like operations, and treats locked call output types as authoritative.
- angr links recovered variables after `VariableRecoveryFast`, runs Typehoon,
  and unifies live variable identities rather than formatting raw registers.
- Kuna carries type facts per Varnode through COPY, MULTIEQUAL, and INDIRECT
  operations in a bounded fixed point before constructing HighVariables.

Glaurung now does the corresponding minimum safe operation for pointers:

1. seed string literals, stack addresses, and named calls with known pointer
   return contracts;
2. propagate across exact copies and compatible selects to a bounded fixed
   point;
3. require every definition of the destination to agree;
4. reject a candidate used in integer, bitwise, cast, or address arithmetic;
5. render explicit representation casts where pointer facts cross the current
   width-only memory model.

The last two conditions are important. A value called `var7` is not inherently
a source pointer, and a four-byte store of pointer bits is not evidence that the
destination has an `int *` source type.

## Real round-trip test

The RED fixture compiles a real GCC ELF containing `getenv("PATH")` and a
literal fallback, decompiles its real exported functions, and recompiles the
generated C under `-std=gnu11 -Werror` with the system `stdlib.h`.

Before the change, the essential output was:

```c
long lookup_path(void) {
    long local_8;
    long var1;
    var1 = getenv("PATH");
    local_8 = var1;
    return local_8;
}
```

After the change, the exact pointer identity survives:

```c
char * lookup_path(void) {
    char * local_8;
    long rsp;
    char * var1;
    rsp = (rsp - 16);
    var1 = getenv((const char *)("PATH"));
    local_8 = var1;
    return local_8;
}
```

The literal-return companion is also emitted as `char *` and recompiles with
warnings promoted to errors.

## Blinded DecBench evidence

The sample binaries were treated as static-only inputs. They were decompiled
but never executed or emulated.

The official upstream DecBench function splitter, context declaration builder,
matching compiler selection, producer flags, and diagnostic fixup loop were
replayed sequentially over all 250 functions:

| outcome | retained baseline | this checkpoint |
|---|---:|---:|
| compilable functions | 123 | 127 |
| compile gains | - | 4 |
| compile losses | - | 0 |

The four newly compilable functions are:

- `bin_062.c:sub_1492` - `malloc` result becomes `void *`;
- `bin_109.c:sub_d3d7` - `strchr` result becomes `char *`;
- `bin_113.c:sub_2e790` - `strdup` result becomes `char *` with an explicit
  width-only store cast;
- `bin_162.c:sub_3d32` - `strncpy` result becomes `char *`.

The retained submission artifact is
`glaurung-results-7bee103.zip`, labeled with source commit
`7bee1038fb72c2c43f257b9ade08467b20a24f0b`. Its SHA-256 is
`b16b387e7547a8275a3cb0645beed677ed784cdb1560622cbfeace8a4e825026`.
The concatenated C payload hash matches the measured pre-commit archive exactly.

For every one of the 123 functions compilable in both archives, the normalized
recompiled assembly is byte-for-byte identical. Consequently the retained byte
score cannot decrease: all prior successful scores are unchanged, old failures
remain zero, and the four new scores are non-negative.

The blinded binaries contain neither a symbol table nor DWARF function ranges,
so the local evaluator cannot extract ground-truth bytes for the four new
functions. Their exact byte-match and type-match increments remain evaluator
results; this checkpoint does not invent them.

## Gates and known independent failures

- `cargo test --lib`: 1,282 passed, zero failed.
- real compiled/decompile/recompile fixture file: 35 passed, zero failed.
- `cargo fmt --check`: passed.
- `cargo clippy --all-targets` and the Python-extension variant: passed with the
  repository's existing warnings.
- touched Python test: Ruff passed; ty reports the file's eight existing
  unresolved harness-module/pytest-stub diagnostics.
- raw 56-lane behavior corpus: 459 pass, 82 known semantic failures, 82 known
  structural results, zero missing lanes and zero infrastructure errors.

The committed behavioral baseline currently predates the newer output-prototype
recovery and reports two independent `cpp_raii_guard` O2 regressions (GCC and
Clang): a value both stored and returned in the ABI register is classified as
void. This pointer-propagation path sees no `varN` in that function and does not
change its output. The stale ratchet is being kept visible rather than refreshed
over a real return-recovery defect.

## Next architectural step

Pointer propagation currently handles exact copies and compatible selects. The
next comparable-to-reference step is a unified typed high-variable layer that
also represents scalar width/signedness, PHI/MULTIEQUAL identities, memory
objects, and callsite prototype constraints. That should replace more renderer
thread-local type state; it should not add another text-level heuristic.
