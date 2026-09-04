# WP6 per-use signedness evidence — 2026-09-04

> **Kind:** record · **Date:** 2026-09-04

## Outcome

The first incremental WP6 constraint slice separates the signedness required by
one machine operation from the source declaration of the value it consumes.
Before this change, `TypeMap` joined every lifetime and register view. An
unsigned range/index use or x86's automatic zero-extension after a 32-bit write
could therefore make a caller-supplied C `int` permanently render as
`unsigned int`.

`src/ir/types_recover/constraints.rs` now records signed and unsigned operand
uses with deterministic `(kind, instruction address, operand index)` identity.
It resolves a declaration signedness only when all informative uses agree.
Contradictory or absent evidence remains unresolved. Equality, address
indexing, and 32-to-64-bit x86 register-write extension are deliberately
neutral; explicit byte/halfword extension, signed or unsigned comparisons, and
arithmetic or logical right shifts remain informative.

The existing `TypeHint` path is retained as an adapter. At the exact SSA
live-in boundary it supplies scalar class and machine width, while the new
constraint set supplies signedness. No second value identity was introduced.

## Real fixture evidence

The RED case uses the committed stripped GCC and Clang O2 builds of
`tests/decompiler_fixtures/src/08_indirect_dispatch.c`. Its source declaration
is:

```c
int tail_dispatch(int tag, int a, int b)
```

Before the implementation, both real binaries rendered:

```c
int tail_dispatch(unsigned int arg0, unsigned int arg1, int arg2)
```

The fixture-backed test now passes for both compilers and asserts the complete
inferred declaration, including the already-correct return width:

```text
uv run pytest python/tests/test_decompiler_observable_parameter_width.py -q
3 passed
```

The same correction removes a false debug-build declaration conflict: inferred
`int (int, int, int)` now agrees with DWARF. The analyst annotation test moved
to `dispatch_switch`, which still has a genuine independently observed conflict,
so removal of the false conflict did not weaken that feature's coverage.

## Validation

```text
cargo test --features python-ext types_recover::constraints --lib --quiet
3 passed

cargo test --features python-ext
3,791 library tests passed, 4 ignored; all integration targets and doc tests passed

uv run maturin develop
fresh extension built successfully

uv run pytest \
  python/tests/test_analyst_prototype_reaches_decompile.py \
  python/tests/test_decbench_type_defect_corpus.py \
  python/tests/test_decompiler_declaration_authority.py \
  python/tests/test_decompiler_observable_parameter_width.py \
  python/tests/test_decompiler_rust_source_types.py \
  python/tests/test_decompiler_signed_division.py \
  python/tests/test_decompiler_wide_arithmetic_width.py \
  python/tests/test_dwarf_types.py \
  python/tests/test_function_prototypes.py \
  python/tests/test_pdb_type_recovery.py \
  python/tests/test_typed_render.py -q
52 passed

uv run python tools/dectest.py @o0 @o2 --jobs 8 --full
SCOPED: 824 lanes of 838 (98%) — no regressions in scope,
27 baseline improvements

uv run python tools/stripped_differential.py
419 stripped lanes; 1,713 comparable cells; no new unrecorded regressions;
ratchet exit 1 from 5 unrecorded improvements and 7 recorded divergences gone
```

The 27 corpus improvements are not attributed to this narrow change: they were
already present relative to the committed baseline. This increment claims the
two directly asserted stripped declaration repairs and the removal of one false
debug declaration conflict. The stripped baseline drift is likewise preserved
for separate review rather than refreshed as part of this type change.

The test census is regenerated at 4,279 declared Rust tests, three more than the
prior record, with zero tests outside every gate.

A subsequent complete ground-truth inventory refresh, made practical by the
per-binary batching recorded in `wp0-known-failure-batching.md`, confirms zero
remaining C parameter-type mismatches across all 1,676 objects. The raw type
axis moved from C 9 / Rust 298 to C 0 / Rust 82. That is strong current-state
evidence, but only the directly asserted `tail_dispatch` cells are attributed
to this commit: several other decompiler increments landed since the preceding
full inventory, so the larger aggregate delta is deliberately not assigned to
WP6 signedness alone.

## Scope and limits

This is not the complete WP6 solver. Equality, width, pointer, pointee,
aggregate, ABI, load/store, call, confidence, and conflict-reporting work remain
open. It does not repair the separate stripped `tail_dispatch` jump-table
recovery defect; those two differential cells still fail because the indirect
jump body is unrecovered, not because the signature is now wrong.

No DecBench run, publication, issue, comment, or pull request was performed.
