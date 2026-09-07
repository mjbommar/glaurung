# WP3 folded-return expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commits `f30167f7` and `b269a3f2` extend bounded production expression
attribution through every return-folding path in
`src/ir/ast/return_folds.rs` that replaces an ABI result assignment with a
returned value.

- `ret = value; return ret` transfers the deleted definition owner to the
  returned `value` subtree.
- `ret = C; return C` transfers the redundant assignment owner to the retained
  constant expression.
- Exhaustive `if` and `switch` joins transfer each arm's terminal definition
  owner to that arm's returned value. Shared epilogue, `break`, and return
  owners remain statement-level control provenance.

In both cases the surviving return statement continues to own the union of the
definition and return instructions. The returned expression owns only the
instruction that established its value; the return instruction remains a
control-transfer owner at statement level.

This is a bounded WP3 producer migration, not universal expression
attribution or WP3 completion.

## Focused evidence

All four ownership assertions were observed red before their implementations:
the surviving statements already held the correct union, but their returned
expressions reported no origin. After the implementations, the complete
touched module passes:

```text
cargo test --features python-ext 'ir::ast::return_folds::tests::' --lib
7 passed; 0 failed
```

An earlier attempted invocation combined `--exact` with an unqualified test
name and executed zero tests. It is explicitly not counted as evidence.

The final required release extension rebuild completed in 35.97 seconds. Four
exact host O0 cells cover the simple/conditional and exhaustive-switch shapes:

```text
uv run python tools/dectest.py \
  '01_conditional_polarity:*:O0:classify' \
  '106_switch_shapes_dense_sparse:*:O0:dense_switch' \
  --jobs 2 --full --show
4 passed; 0 regressions in scope
```

The expression carrier is render-transparent, so visible C remains unchanged.
No full Rust, Python, architecture, fixture, or DecBench sweep was run at this
bounded iteration boundary.

## Next boundary

Continue with the next transformation that removes an expression-defining
statement. Preserve the same ownership split, audit newly exposed
non-exhaustive matchers, and validate only the touched module and smallest
representative real-binary slice until the next coherent WP3 integration gate.
