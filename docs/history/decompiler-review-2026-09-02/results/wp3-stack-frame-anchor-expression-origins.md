# WP3 stack-frame anchor expression origins

> **Kind:** record · **Date:** 2026-09-10

## Outcome

Commit `9bcff448` makes the prepared-AST stack-object pass read the source of an
x86 frame-pointer assignment through expression ownership. A semantic
`rbp = rsp` no longer becomes a false “repurposed rbp” merely because the stack
register carries an instruction-origin wrapper.

The proof remains exact: the calling convention must be x86, the destination
must have frame-register storage identity, and the semantic source must have
stack-register storage identity. Casts and unrelated sources still fail closed.

## Focused TDD

The existing opaque-identity frame-anchor contract now attributes the source
register. Before repair it returned `Some(false)` instead of `Some(true)`. After
repair, that contract and the two adjacent safety controls pass:

```text
frame_anchor_detection_uses_exact_identity_not_display_spelling: pass
repurposed_rbp_value_is_not_promoted_as_a_stack_object_address:  pass
a_cfa_object_is_left_alone_when_the_frame_pointer_is_established: pass
```

An exact detached release build of `9bcff448` was fresh. The two directly
relevant x86-64 GCC Hello round trips pass:

```text
symbols-pie-O0-gcc: pass
symbols-pie-O2-gcc: pass
```

O0 covers a conventional established frame and O2 covers the omitted-frame
control. No broad Rust, Python, fixture, DecBench, or Joern suite ran, and the
full six-cell cross-architecture Hello checkpoint was not repeated.

This closes one residual frame-classification reader, not WP3 or WP9. Universal
SSA identity, explicit invalidation, and the remaining architecture/storage
consumer audit stay open.
