# WP3 ARM32 frame identities

Status: bounded production consumer migration landed at `5fdb7906` on
`agent/wp5-next-switch`.

## Result

The production AAPCS frame recognizer now resolves `sp`, `fp`/`r11`,
`lr`/`r14`, core callee saves, and VFP callee saves through exact
`ValueIdentities`. Prologue parsing, nested epilogue matching, frame
deallocation, restore matching, and residual-SP refusal all share that same
authority.

An exact negative contract maps values literally spelled `sp#0` and `lr#0` to
`r0` and proves neither can impersonate machine frame state. Opaque values
mapped to exact `sp` and `r14` identities are recognized. Missing or ambiguous
identity declines the production transformation. Display-name parsing remains
only in the no-sidecar compatibility entry point used by legacy unit callers.

## Focused evidence

```text
cargo test --lib --features python-ext ir::arm32_prologue::tests -- --nocapture
10 passed; 4,455 filtered out

uv run maturin develop
completed

uv run pytest python/tests/test_decompiler_arm_frame_spills.py -q
1 passed
```

No broad Rust/Python suite, fixture matrix, DecBench, or Joern run was used for
this identity-only migration.

## Scope boundary

This removes the ARM32 architecture-specific production `#version` parser from
the WP3 semantic-reader inventory. It does not remove the value-numbering tag
representation, complete expression-origin propagation, or close WP3's
universal invalidation and attribution criteria.
