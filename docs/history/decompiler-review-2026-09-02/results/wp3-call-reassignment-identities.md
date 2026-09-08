# WP3 call-reassignment identities

Date: 2026-09-08

Source commit: `e0c5fc11`

## Change

Recovered-layout and ordinary call folding must not move an argument
expression across a statement that rewrites a value it reads. That hazard was
previously limited to destinations whose presentation name contained
`#version`. The production path now records destinations owned by the
`ValueIdentities` sidecar and compares their SSA candidate sets with every
register read by the expression.

Opaque role aliases of the same SSA value therefore still block unsafe motion,
while distinct versions of the same physical register do not create a false
hazard. The spelling parser remains only in the explicit no-sidecar
compatibility path.

This advances WP3's semantic-reader migration. It does not remove `tag_phys` or
complete the remaining call-recovery audit.

## Focused validation

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext --lib \
  ir::call_args::tests::opaque_argument_reassignment_is_detected_by_value_identity \
  -- --exact
1 passed; 0 failed; 4,501 filtered out

cargo test --features python-ext --lib \
  ir::call_args::tests::distinct_argument_identities_do_not_create_a_false_reassignment \
  -- --exact
1 passed; 0 failed; 4,501 filtered out

uv run maturin develop
passed; debug extension rebuilt

uv run python tools/build_guard.py
fresh; native SHA-256 a7b6f00ae725ded6f538d01a59cd6008d212d1aac9ccad9821cbffc3fefb2188

uv run python tools/dectest.py 11_call_shapes:gcc:O2:call_accumulate_bytes --show
1 of 838 lanes selected; no regression in scope
```

No broad Rust or Python suite, fixture sweep, DecBench run, or Joern run was
performed for this bounded increment.
