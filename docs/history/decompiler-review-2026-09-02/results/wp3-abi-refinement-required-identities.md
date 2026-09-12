# WP3 ABI refinement requires identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `6ef3ba30` removes the production no-sidecar entry point from
prepared-AST ABI-width refinement. Both declaration and width-map calls now
require the pipeline-owned `ValueIdentities` sidecar. High-half parameter
proofs, ordinary value eligibility, and promoted-store exclusion no longer
parse `argN`, `varN`, or `local_N` display names.

The old AST-only helpers are test-only scaffolding. They construct explicit
identities from each test's type map before calling the production API, so the
shipped library contains no fallback route. A new negative contract proves
that an unowned value named `local_looks_promoted` remains a pointer store;
only explicit promoted-object ownership excludes that store from pointer-width
observation.

## Focused validation

```text
ir::ast::abi_widths::identity_tests: 5 passed, 0 failed
ir::ast::tests::decbench_*:          66 passed, 0 failed (0.21 s)
four exact adjacent width/return tests: pass
cargo check --lib --features python-ext: pass
```

After a fresh release extension build, four directly relevant Python checks
passed:

```text
test_stripped_aggregate_cursor_preserves_byte_stride_and_execution
test_real_pointer_locals_keep_value_identity_across_round_trip
test_clang_packed_sign_mask_round_trips
test_clang_packed_qword_unpack_round_trips
```

No full Rust, Python, fixture, DecBench, or Joern suite ran. The 66-test Rust
selection is the existing fast `decbench_` AST-render group, not the binary
fixture matrix.

## Scope

This closes display-name authority in the ABI-width refinement pass. It does
not complete WP3's remaining declaration, parameter-spill, copy-propagation,
or naming consumers, nor the universal expression-origin audit.
