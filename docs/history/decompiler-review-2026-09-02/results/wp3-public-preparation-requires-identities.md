# WP3: public AST preparation requires value identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `a89a6e52` removes five identity-free transformations from the external
Rust library surface in non-test builds:

- `ast::prepare_for_decbench`;
- `ast::prepare_for_decbench_with_output`;
- `ast::settle_copies_and_constants`;
- `const_fold::fold_constants`; and
- `copy_prop::propagate_copies`.

The AST preparation wrappers remain compiled only for unit-test compatibility.
The standalone copy and constant passes are crate-private because the shared
internal preparation implementation still selects them through its explicit
`Option<identities>` compatibility branch. Production callers and benchmarks
continue to use the identity-required variants.

Two repository examples had drifted behind the earlier naming cutover.
`check_canary` now retains the value-numbering sidecar through typed lowering
and constant folding, performs role naming only on a final cloned render view,
and never mutates the semantic AST for presentation. `check_prologue` no longer
names the AST before running architecture cleanup.

## Red/green evidence

Gating the legacy copy/fold functions outright was observed red in a non-test
library build: the internal optional preparation implementation still
referenced both functions (`E0425`). They were therefore narrowed to
crate-private rather than falsely claimed deleted. A subsequent all-target
compile found the stale `check_prologue` import (`E0432`); all examples compile
after its migration.

```text
cargo check --features python-ext --lib
exit 0

cargo check --features python-ext --examples
exit 0

cargo test --features python-ext --lib ir::ast::prepare::fixpoint_tests:: \
  -- --test-threads=1
4 passed; 0 failed

cargo test --features python-ext --lib \
  ir::copy_prop::tests::attributed_pure_value_propagates_without_losing_its_origin \
  -- --exact --test-threads=1
1 passed; 0 failed

cargo test --features python-ext --lib \
  ir::const_fold::tests::exception_expressions_share_the_constant_fold_surface \
  -- --exact --test-threads=1
1 passed; 0 failed

cargo run --features python-ext --example check_canary
exit 0

uv run maturin develop
exit 0
```

The example run is a real-binary no-crash check, not an output-quality result:
its hard-coded function produced none of the stack/canary debug rows that the
example filters for. No corpus matrix, DecBench, or Joern run was performed.
The native build included unrelated concurrent dirty source and therefore is a
live-tree build check rather than exact-clean commit provenance.

## Remaining boundary

The shared internal preparation implementation still accepts
`Option<&ValueIdentities>` and compiles spelling-based branches. The next WP3
increment must make its production signature identity-required and confine any
legacy AST inference to `#[cfg(test)]` helpers. This commit narrows the supported
API; it does not claim that internal compatibility branch is gone.
