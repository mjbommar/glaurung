# WP3 pointer refinement requires identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `1e247c46` removes the no-sidecar compatibility path from prepared-AST
pointer refinement and its memory-object input. The production renderer must
now provide its pipeline-owned `ValueIdentities`; a value cannot qualify as an
SSA value, source parameter, promoted stack object, trusted copy source, or
character-pointer cursor merely because its displayed name resembles `varN`,
`argN`, `local_N`, or `stack_N`.

The identity gate is fail-closed. Missing or ambiguous SSA ownership declines
ordinary value refinement, and a promoted object must be explicitly recorded
in the sidecar. Tests that exercise legacy-looking names now construct those
facts explicitly rather than selecting a production spelling fallback.

## Focused validation

Only the owning Rust modules were selected:

```text
ir::high_variables::tests: 37 passed, 0 failed, 4,798 filtered out
ir::memory_objects::tests:  11 passed, 0 failed, 4,824 filtered out
```

A fresh release extension build then passed the two directly owning binary
checks:

```text
test_stripped_aggregate_cursor_preserves_byte_stride_and_execution: pass
test_real_pointer_locals_keep_value_identity_across_round_trip: pass
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The six-cell
Hello checkpoint was not repeated because it passed immediately before this
increment and these two release checks exercise the changed type and
memory-object path directly.

## Scope

This closes the remaining display-name authority inside `high_variables` and
the prepared-AST memory-object adapter. It advances WP3's consumer migration;
it does not complete the remaining semantic-consumer audit, universal origin
attribution, or WP3 as a whole.
