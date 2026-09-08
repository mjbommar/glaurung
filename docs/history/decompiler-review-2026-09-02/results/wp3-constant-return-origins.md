# WP3 constant-return cleanup origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `7c2fc34b` makes late redundant constant-return cleanup transparent to
statement origins. An attributed `ret = C; return C;` now becomes the same
single return as its unwrapped form, including inside supported structured
bodies.

The deleted assignment and surviving return express one source operation, so
their exact instruction origins are unioned onto that return. Mismatched
constants and non-return storage remain unchanged.

## Focused evidence

The attributed test was observed red before repair because both statements
remained. After repair the single return owns both addresses.

```text
cargo test --features python-ext \
  ir::ast::return_folds::tests::attributed_late_return_cleanup_moves_assignment_owner_to_return \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::ast::return_folds::tests
4 passed; 0 failed
```

A fresh release extension was built in 34.71 seconds. The two exact host O0
review functions remain execution-correct:

```text
uv run python tools/dectest.py \
  '01_conditional_polarity:*:O0:classify' --jobs 2 --full --show
2 passed; 0 regressions in scope
```

No broad Rust, Python, architecture, fixture, or DecBench sweep was run.

## Next action

Continue through `ast/return_folds.rs` in bounded transformations. The
exhaustive-if and exhaustive-switch folds still traverse and match raw
statements and require explicit hoist/duplication ownership tests.
