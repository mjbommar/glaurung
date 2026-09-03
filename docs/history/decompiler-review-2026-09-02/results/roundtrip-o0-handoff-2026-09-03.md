# O0 round-trip improvement handoff

> **Kind:** implementation handoff  
> **Date:** 2026-09-03  
> **Scope:** the shared dirty checkout; no commit or baseline refresh is claimed

## Outcome

This work period moved the checked-in execution baseline by **33 passing
function/lane cells with zero regressions** in the final selected O0/O2 sweep:

```text
uv run python tools/dectest.py @o0 @o2 --jobs 8 --full

SCOPED: 824 lanes of 838 (98%)
IMPROVEMENTS: 33
REGRESSIONS: 0
```

The baseline files were deliberately not refreshed. They still expose the 33
improvements until the concurrent implementation lanes are reconciled and a
single merge-ready gate is run.

This is material progress toward clean round-trip C, especially at `-O0`, but
it is not completion. The broader objective remains open.

## Working method

The implementation loop was:

1. select one small failing source function;
2. inspect source, emitted C, execution failure, disassembly/pass dumps, and
   recovered types;
3. locate the earliest shared semantic boundary that lost the fact;
4. add a focused positive test and a fail-closed negative control;
5. rebuild the release Python extension;
6. run the exact GCC/Clang fixture cells;
7. run the full selected O0/O2 execution sweep and require zero regressions.

The rule was not to recognize fixture names or substitute source templates.
Changes belong in reusable boundaries: machine lifting, stack-object recovery,
call contracts, readonly-data interpretation, type/declaration planning, AST
preparation, or rendering.

Behavioral equivalence and canonical source quality remain separate claims.
`dectest` proves the former for its generated inputs; exact Hello tests and
source/output inspection address the latter.

## Canonical Hello World seam

Three exact-output test modules now define the intended smallest-program
contract:

- `python/tests/test_linux_x86_64_hello_canonical.py`
- `python/tests/test_linux_arm_hello_canonical.py`
- `python/tests/test_mingw_hello_canonical.py`

The expected result is one stable translation unit:

```c
int main(void) {
    extern int puts(const char *);
    puts("Hello, World!");
    return 0;
}
```

The tests cover Linux x86-64 GCC/Clang O0-O3 PIE and non-PIE, symbol-bearing
and stripped binaries; Linux AArch64/ARMv7 cross-GCC O0-O3 in the same dynamic
layouts; selected stripped static Linux builds; and MinGW x86-64/i686 O0-O3,
with and without symbols. They are the right conformance seam, but their full
matrix was not rerun as part of this final closing gate.

Still absent from the exact Hello grid are PGO, LTO, a dedicated shared-object
Hello case, musl, Mach-O/macOS, MSVC/clang-cl, ARM Clang, RISC-V, static MinGW,
and version-pinned multi-release compiler/libc cells.

## Important improvements made

### Prologues, frames, and ABI cleanup

The shared checkout gained substantial x86, ARM32, and ARM64 prologue/frame
handling, target-aware register views, call-result and parameter-slot cleanup,
and output-register residue suppression. These changes are responsible for a
large part of the improvement in ordinary O0 code: stack homes and saved frame
state are less likely to leak into source C.

### Function and library contracts

Call-contract recovery and rendering now preserve more authoritative
prototypes, direct-output effects, variadic format information, and library
semantics. The concurrent FLIRT-library work builds relocation-masked
signatures from real archives, retains function length as a disambiguator,
handles ARM Thumb addresses and i386 relaxation, and coalesces same-address
aliases toward public names such as `puts`.

Dynamic binaries normally obtain `puts@GLIBC_*` from ELF import/version data;
static stripped binaries need archive-derived identity. Both paths should feed
the same `puts(const char *)` semantic contract. A GLIBC symbol version is an
ABI requirement, not by itself proof of the complete installed glibc release.

### Stack objects and static locals

Stack-slot joining now treats future direct reads as object boundaries instead
of depending on traversal order. This fixed an adjacent-canary/object merge in
the nested TLV fixture. Static local identity and portable backing storage also
improved, accounting for six baseline improvements across counters and static
tables.

### Strings and readonly values

An exact-sized character array containing an embedded NUL is no longer
misclassified as the shorter C string ending at its first NUL. Escape-sequence
fixtures now pass across GCC/Clang O0/O2.

Signed upper-bound recognition for guarded readonly lookups was extended while
requiring a prior nonnegative proof. This recovered additional X-macro table
lookups without interpreting an unbounded signed index as safe.

### Pointer arithmetic

Machine address displacements are now reconciled with the C type that is
actually declared. Before:

```c
*(int *)(interior - 0x4)
```

Because C scales `int *` arithmetic, that subtracts 16 bytes, not the four
bytes represented by the machine instruction. The new output is:

```c
*(int *)(interior - 1)
```

Non-integral element displacements remain explicit integer-byte arithmetic,
and opaque aggregate pointers decline scaling. The exact Clang O0 fixture moved
from fail to pass; GCC remained passing.

### Relocated pointer tables

Readonly folding now handles guarded `*table[index]` where `table` is a
relocation-fixed array of pointers to readonly scalars. It follows only proven
in-image relocation targets and materializes their exact values. If any slot,
target, bound, width, or readonly value is missing, the transform declines.

For `const_array_of_pointers`, both GCC and Clang O0 moved from fail to pass,
and the final broad sweep also found GCC O2 improving. The portable core now
looks like:

```c
(which == 0) ? 7 : (which == 1) ? 8 : (which == 2) ? 9 : fallback_load
```

The fallback preserves best-effort output outside the proved guarded domain.

## Measured improvement clusters

The final 33-cell delta includes:

- six static-local cells;
- four embedded-NUL/escape-string cells;
- three relocated pointer-table cells;
- two X-macro readonly lookup cells;
- the Clang O0 negative-interior-pointer cell;
- GCC O0 rational arithmetic/comparison cells;
- O0 compound/designated-initializer cells;
- several GCC O0 C++ operator/object-lifetime cells;
- selected optimized packed, unaligned, bitstream, template, AArch64 dispatch,
  and floating-point cells.

The exact list remains reproducible from the unrefreshed baseline with the
command in the Outcome section.

## Validation state

Confirmed at wrap-up:

- release extension rebuilt successfully with `uv run maturin develop --release`;
- focused pointer-scaling unit test passed;
- focused relocated-pointer-table positive and negative-control test passed;
- exact `109_subscript_commutativity:*:O0:negative_offset_from_interior`: 2/2 pass;
- exact `120_const_and_literals:*:O0:const_array_of_pointers`: 2/2 pass;
- final O0/O2 execution sweep: 824 selected cells, 33 improvements, zero
  regressions;
- `git diff --check`: clean.

The renderer test module currently reports 205 passing and six failing tests.
Those six are the already-observed expectation/contract drift involving fixed
width prototypes, aggregate typedef parameters, exact-sized globals, `main`
parameter spelling, and opaque typedefs. Earlier in this work period the full
Rust gate reported 3,157 passing and seven failures: those same six plus the
known session parse-count expectation. These are not represented as green.

The full Python suite was not completed in the shared checkout; an earlier run
was interrupted and included failures from concurrent lanes. CI was not run.
No commit, push, or refreshed baseline is claimed.

After the successful release build and final 824-cell sweep, a closing attempt
to run the complete `ir::readonly_fold` Rust test module encountered a new
concurrent-lane compile error in `src/ir/lift_x86.rs`: a test calls `lift32`,
which is not in that scope. The focused readonly test had passed before that
edit appeared. Therefore the measurements above describe the successfully
built release extension, while the final shared working tree must be rebuilt
after the x86 lifting lane is made coherent.

## What remains

### Highest-value small O0 gaps

1. **Varargs (`113_varargs`)** — recover `va_list` setup/iteration and variadic
   argument widths without exposing ABI save-area mechanics.
2. **Qualifier-bearing pointers (`128_qualifier_combinations`)** — preserve
   `const` placement and writes through the correct pointer layer.
3. **VLA/`sizeof` (`123_sizeof_semantics`)** — distinguish evaluated VLA size
   expressions from compile-time `sizeof` constants.
4. **Struct values (`111_self_referential_struct`, `129_struct_by_value`)** —
   stop frame aliases and ABI aggregate carriers leaking into field-level C.
5. **Non-local control flow (`102_duffs_device`, `103_computed_goto`)** — retain
   a total, executable fallback while improving source structure.

The `112_recursion_shapes:*:O0:tail_countdown` failures should not drive a
decompiler rewrite: the emitted recursive C is source-faithful, while the
differential harness crashes from stack exhaustion on an adversarial
`INT_MAX` input. Fix or classify the harness case instead of turning recovered
recursion into an invented loop.

### Quality cleanup after semantic closure

Even passing functions still contain noisy casts, unsigned return wrappers,
temporary result locals, expanded range predicates, and fallback absolute
loads. Once behavior is stable, improve canonical source shape with rules that
are type- and definedness-proved, then score exact/readability output separately
from execution.

### Matrix expansion

Expand the exact Hello grid in this order:

1. shared `-fPIC`, all optimization levels, and static O1/O3;
2. LTO and reproducible PGO profiles;
3. musl alongside glibc;
4. ARM Clang and RISC-V;
5. Mach-O/Apple Clang;
6. clang-cl/MSVC and static Windows CRT variants;
7. pinned compiler and libc version containers.

## Resume instructions

1. Treat the current checkout as shared and dirty; inspect ownership before
   staging or reverting anything.
2. Rebuild release immediately before measuring because concurrent Rust edits
   can make the editable extension stale.
3. Do not refresh `baseline.json` until concurrent lanes are reconciled.
4. Start with one of the small O0 gaps above, capture source/output and the
   direct harness failure, and add a negative control before changing code.
5. Require the complete `@o0 @o2` sweep to retain zero regressions.
6. Before merge, run the full Rust, Python, exact Hello, structural, def-use,
   stripped, architecture, and CI gates required by the implementation plan.
