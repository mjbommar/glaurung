# WP3 vector benchmark requires identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `29380a5b` removes the identity-free wide-vector-copy entry point from
non-test builds. The shipped decompiler already used
`recover_wide_copies_with_identities`; the remaining non-test caller was the
composed decompile benchmark, which incorrectly discarded the identity
sidecar returned by value numbering and exercised the spelling-based fallback.

The benchmark now calls
`value_number_with_parameter_slots_lifetimes_and_identities`, carries the
resulting `ValueIdentities` in its prepared state, and supplies it to vector
recovery in cold, warm, whole-binary, phase-prepared, and timed dataflow paths.
Its documented context-free AST subset remains a lower bound on the shipped
pipeline, but this pass now measures the same semantic route as production.

Hand-written vector unit tests retain a private, `cfg(test)` compatibility
helper. Their legacy names are fixture syntax rather than a callable product
API.

## Focused evidence

After the public fallback was removed, the benchmark build failed as expected:

```text
error[E0425]: cannot find function `recover_wide_copies` in module
`glaurung::ir::vector_copy`
```

After threading the sidecar:

```text
ir::vector_copy::tests:                    11 passed, 0 failed
cargo check --features python-ext
  --bench decompile_pipeline:              passed
cargo bench --bench decompile_pipeline
  --no-run:                                passed
```

`uv run maturin develop` completed and `tools/build_guard.py` reported
`fresh`, with native SHA-256
`12f3283cff6b97c0e8bde3d33dbc75685403e10d36b609a84d4ac0f4340c2433`.
As in the preceding increment, the extension includes concurrent unstaged
shared-worktree changes, so this is live-tree build evidence rather than an
exact-clean-checkout artifact.

No benchmark timing claim is made: this increment fixes route fidelity and
only builds the benchmark executable. No test census changes. No broad Rust,
Python, fixture, DecBench, or Joern suite ran.

## Scope

No non-test caller can invoke spelling-based vector-copy recovery. The general
copy/constant fixpoint still exposes no-sidecar entry points for the isolated
`ir_dataflow` benchmark and explicit diagnostic/test preparation. Those are
the next compatibility surfaces to classify. WP3 remains incomplete.
