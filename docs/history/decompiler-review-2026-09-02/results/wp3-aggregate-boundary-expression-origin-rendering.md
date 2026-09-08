# WP3 aggregate-boundary expression-origin rendering — 2026-09-08

> **Kind:** record · **Date:** 2026-09-08

Commit `6d8a252b` closes the direct declared-object path at aggregate call and
destination boundaries. It does not generalize aggregate ABI classification or
complete WP3.

## Defect and boundary

The renderer distinguishes two aggregate values:

- a register already declared as the exact source aggregate object, which can
  cross an equally typed call or return directly; and
- a machine carrier whose bits must be reconstructed into the source object
  through a union.

The direct-object checks matched a raw `Expr::Reg`. Adding origins to an exact
`struct pair` parameter therefore produced nested, cancelling unions at both
boundaries:

```c
consume_pair(((union { struct pair object; unsigned long long bits; }){
    .bits = (unsigned long long)(((union {
        struct pair object; unsigned long long bits;
    }){ .object = arg0 }).bits)
}).object);
```

The return repeated the same object-to-bits-to-object cycle. The repair makes
only the two direct-register reads semantic. Exact declared-type equality is
still required, and the existing raw `Deref`/constant carrier tests continue to
require union reconstruction.

## Focused verification

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
cargo test --features python-ext --lib \
  ir::ast::tests::by_value_aggregate_call_reconstructs_the_source_object_from_carrier_bits \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::by_value_aggregate_return_reconstructs_the_source_object_from_carrier_bits \
  -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::by_value_aggregate_parameter_is_read_through_its_machine_carrier \
  -- --exact
uv run maturin develop --release
uv run --no-sync python tools/dectest.py \
  '197_homogeneous_float_aggregates:*:*:hfa197_make_tagged' \
  '197_homogeneous_float_aggregates:*:*:hfa197_consume_pair2d' \
  --full --show
```

Results: all three exact Rust contracts pass with 4,671 unrelated tests
filtered out. In the release fixture slice, the four Clang/GCC O0/O2
`hfa197_make_tagged` cells pass. The four `hfa197_consume_pair2d` cells remain
structural-only, as before; they are not semantic passes. The harness reports
no scoped regression. No broad fixture matrix or whole repository suite ran.

## Next action

Re-audit the remaining raw destination and call readers, especially select-arm
and representation-value special cases. Do not replace machine-carrier fallback
with direct object spelling unless the emitted declaration proves exact type
equality.
