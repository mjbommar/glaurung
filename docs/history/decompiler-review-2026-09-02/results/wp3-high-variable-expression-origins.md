# WP3 high-variable expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `570e505f` makes prepared-AST type propagation and its memory-object
input transparent to expression provenance. Pointer-producing calls and
literals, exact copies, promoted stores, null initializers, high-bit integer
literals, character-pointer arithmetic, affine addresses, and object origins
now classify their semantic expressions rather than rejecting an ownership
carrier.

This improves source declarations and pointer arithmetic without weakening the
existing fail-closed rules for ambiguous identities, incompatible definitions,
unsafe integer uses, or conflicting object extents.

## Focused TDD

Three existing contracts were strengthened with expression owners. Before the
repair all three failed: a high-bit constant remained incorrectly signed, a
known call/literal chain lost its pointer declarations, and an aggregate cursor
lost its byte-pointer model. After the repair:

```text
ir::high_variables::tests: 35 passed, 4,661 filtered out
ir::memory_objects: 33 passed, 2 ignored, 4,661 filtered out
```

## Release real-binary evidence

A clean detached `--release` build at `570e505f` passed only the two directly
owning binary checks:

```text
test_stripped_aggregate_cursor_preserves_byte_stride_and_execution: pass
test_real_pointer_locals_keep_value_identity_across_round_trip: pass
```

No broad Rust, Python, fixture, DecBench, or Joern run was performed. The
six-cell Hello World checkpoint was not repeated because it ran immediately
before this increment and this batch has direct type/memory-object witnesses.

## Scope

This closes the bounded high-variable and affine-memory-object expression
consumer surfaces. It does not complete universal expression attribution, the
remaining wildcard audit, or the general WP6 constraint solver.
