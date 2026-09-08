# WP3 x86 frame identities

Status: bounded production consumer migration landed at `a7762f05` on
`agent/wp5-next-switch`.

## Result

The production x86-64 omit-frame-pointer recognizer now classifies callee-save
sources and matches their restores through `ValueIdentities`. It no longer
strips `#version` from rendered register names to decide whether two values
belong to `rbp`, `rbx`, or `r12` through `r15`.

An exact negative contract maps a value literally spelled `r15#0` to `rax` and
proves it is not accepted as a callee save. An opaque value mapped to the exact
`r15` identity is accepted. Missing or ambiguous production identity declines
the frame transformation. The old spelling behavior remains only in the
explicit no-sidecar compatibility entry point used by legacy unit callers.

## Focused evidence

```text
cargo test --lib --features python-ext ir::x86_prologue::tests -- --nocapture
40 passed; 4,424 filtered out

uv run maturin develop
completed

uv run pytest \
  python/tests/test_decompiler_fixture_harness.py::test_real_x86_stack_clash_frame_does_not_expose_callee_save_inputs -q
1 passed
```

The real-binary test recompiles the recovered C with uninitialized-use
warnings promoted to errors and compares seven inputs against the original
binary. No broad suite or corpus was run for this identity-only migration.

## Scope boundary

This removes one production `#version` parser from the WP3 semantic-reader
inventory. Cdecl32 compatibility recognition and ARM32 frame recognition are
separate consumers. WP3 remains open until every production consumer is typed,
SSA invalidation is universal, and origins survive every enabled pass.
