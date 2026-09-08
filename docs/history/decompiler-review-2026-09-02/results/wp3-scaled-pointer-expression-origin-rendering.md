# WP3 scaled-pointer expression-origin rendering — 2026-09-08

> **Kind:** record · **Date:** 2026-09-08

Commit `a8078d9a` closes one pointer-arithmetic origin seam in the typed C
renderer. It does not complete WP3's universal attribution or general array
reconstruction.

## Defect and boundary

When a declared pointer plus an integral byte displacement exactly matches its
pointee width, the renderer uses native C scaling: eight bytes on `long *`
becomes `p + 1`. If that pointer-valued subexpression participates in a larger
machine byte-address calculation, it must first cross back to `(long)(p + 1)`;
otherwise C scales the enclosing dynamic offset by `sizeof(*p)` again.

Origins were added around the pointer register, displacement, and nested
addition in the existing exact contract. Before the repair, the renderer lost
both the native scaling proof and the explicit nested pointer boundary:

```c
result = (long)((((long)p + 8) + (i * 8)));
```

The repair makes only the pointer-arithmetic shape reads semantic. Operation
kind, exact divisibility by the declared pointee width, displacement value,
and the rule that non-integral displacements stay byte arithmetic are unchanged.
Afterward the nested term is again rendered as `(long)(p + 1)` before adding
`i * 8`.

## Focused verification

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
cargo test --features python-ext --lib \
  ir::ast::tests::nested_scaled_pointer_offset_returns_to_byte_arithmetic \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::declared_local_pointer_width_overrides_machine_carrier_width \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::dwarf_local_pointer_arithmetic_keeps_machine_byte_offsets \
  -- --exact
uv run maturin develop --release
uv run --no-sync python tools/dectest.py \
  '207_scaled_index_addressing:*:*:word_at_index' --full --show
```

Results: all three exact Rust contracts pass with 4,671 unrelated tests
filtered out. All four selected Clang/GCC O0/O2 fixture lanes pass with no
regression in scope. No broad fixture matrix or whole repository suite was run.

## Next action

Finish the nearby aggregate destination and call-argument direct-register
readers, then re-audit this renderer file for raw shape matches that still
disagree with already-origin-transparent type or representation proofs.
