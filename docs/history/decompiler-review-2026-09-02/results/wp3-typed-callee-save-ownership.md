# WP3 typed callee-save ownership

Status: bounded production increment landed on `agent/wp5-next-switch` at
`521d9524`; integration and broad release gates remain separate work.

## Result

Stack promotion now records which promoted objects hold exact SSA version-zero
callee-saved machine values. Frame cleanup consumes that fact instead of
recovering register identity from display names such as `r15#0`.

The same focused real-binary check exposed an older stack-clash defect: late
copy propagation turned probe load/store pairs into `local_1028 = local_1028`
and `local_2028 = local_2028`. A clean parent build at `d9a2303c` reproduced
the failure. The repair removes a self-store only when stack promotion itself
published the destination as a promoted object; an unowned bare-register
pointer store remains intact.

## Focused evidence

All iteration checks were limited to the changed semantic boundary:

```text
cargo test --lib --features python-ext callee_save -- --nocapture
15 passed; 4,448 filtered out

cargo test --lib --features python-ext \
  promoted_self_store_is_removed_but_pointer_self_store_is_preserved -- --nocapture
1 passed; 4,462 filtered out

uv run pytest \
  python/tests/test_decompiler_fixture_harness.py::test_real_x86_stack_clash_frame_does_not_expose_callee_save_inputs \
  python/tests/test_decompiler_arm_frame_spills.py -q
2 passed
```

The x86 fixture recompiles with GCC's uninitialized-use warnings promoted to
errors and compares the original and recovered functions at seven inputs.
`uv run maturin develop` completed after the final Rust edit. No fixture-wide,
DecBench, Joern, or whole Python run was used during iteration.

## Scope boundary

This advances WP3's stable-value consumer migration and repairs one adjacent
WP10 definedness regression. It does not complete authoritative SSA,
invalidation/origin tracking, WP2 pipeline unification, or the release gate.
