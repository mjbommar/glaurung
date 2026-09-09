# WP3 memory-object store expression origins

> **Kind:** record · **Date:** 2026-09-10

## Outcome

Commit `1c8b303e` makes promoted-stack store classification in the prepared-AST
memory-object adapter transparent to expression ownership. An attributed store
address whose semantic value is a pipeline-owned promoted object is again read
as a scalar definition, rather than being mistaken for an indirect write that
destroys the object's origin and stride evidence.

The identity gate is unchanged. An unowned register remains a pointer store,
and the existing extent, stride, access-width, and conflict rules remain
fail-closed.

## Focused TDD

The existing opaque promoted-cursor contract was strengthened so its direct
store addresses carry expression owners. Before repair it failed with no
recovered extent (`None` rather than `Some(64)`). After repair:

```text
opaque_promoted_cursor_recovers_object_by_identity: 1 passed
ir::memory_objects::tests:                          11 passed
```

An exact detached release build of `1c8b303e` was fresh, and the directly
owning real-binary round trip passed:

```text
test_stripped_aggregate_cursor_preserves_byte_stride_and_execution: pass
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The periodic
six-cell Hello checkpoint was not repeated because it passed immediately before
this increment.

This closes one residual prepared-AST semantic reader, not WP3. Authoritative
SSA identity, explicit invalidation, and the remaining consumer audit stay
open.
