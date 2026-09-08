# WP3 x86 scalar-frame storage identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `21599ad4` removes `stack_`/`local_` display-name authority from the
production x86-64 scalar rbp-frame recognizer. Its prologue and recursively
visited epilogues now accept an opaque promoted slot only when the pipeline's
`ValueIdentities` owns it, and reject an unowned `stack_0`. Typed
`Expr::StackAddr` nodes are accepted on their explicit AST semantics rather
than redundantly checking their object's rendered name.

The cdecl32 realignment recognizer is a separate pre-sidecar compatibility
consumer and remains open. This increment therefore advances but does not
complete WP3.

## Focused evidence

```text
cargo test --features python-ext --lib \
  'ir::x86_prologue::tests::identity_aware_scalar_frame' -- --nocapture
2 passed; 0 failed

cargo test --features python-ext --lib \
  'ir::x86_prologue::tests' -- --nocapture
42 passed; 0 failed

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run pytest -q \
  python/tests/test_decompiler_fixture_harness.py::test_real_x86_stack_clash_frame_does_not_expose_callee_save_inputs
1 passed
```

The `--lib` filters avoid enumerating unrelated integration-test harnesses.
While the census was generated, a concurrent uncommitted decoder lane added
three disassembler tests to the shared checkout. Corrective commit `681594ed`
records only this increment's two tests: 5,164 declared, 2,459 in `ir`, 21 in
`disasm`, and zero outside a gate. An isolated archive of the exact pushed tip
reproduces that JSON and passes all six census tests.

No broad Rust/Python suite, fixture matrix, corpus, DecBench, or Joern run was
made. The recent four-cell Hello checkpoint was not repeated for this storage-
identity seam.

## Next ordered increment

Continue the audit with the cdecl32 frame path or the next enabled semantic
reader only after confirming where an authoritative sidecar is available. Do
not generalize compatibility parsing into production evidence.
