# WP3 one-armed select expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `7b1d072a` makes one-armed select rendering transparent to an
expression-origin carrier around the select. A safe expression of the form
`condition ? update : destination` can therefore retain the clearer
initializer-plus-`if` spelling after provenance is attached, instead of
regressing to a ternary assignment solely because the outer AST variant is
`Expr::Origin`.

The existing semantic proof is unchanged: the condition cannot read the
destination, the initializer must be safe to evaluate eagerly, and the update
cannot depend on the overwritten old value. Both the ordinary and typed C
renderers share this helper. The attributed expression itself is not rewritten,
so its origin carrier remains intact.

This is a bounded WP3 scored-text consumer migration. It does not make unsafe
or effectful selects eager, complete universal expression attribution, or
complete WP3.

## Focused verification

`attributed_select_keeps_one_armed_statement_rendering` was observed red first:
the helper returned no match for an attributed safe select. After the repair it
passes and directly asserts that rendered output contains the structured `if`
and no ternary operator.

```text
cargo test --features python-ext --lib \
  ir::ast::lower_conds::tests::attributed_select_keeps_one_armed_statement_rendering \
  -- --exact
1 passed; 0 failed; 4,704 filtered out

cargo test --features python-ext --lib \
  'ir::ast::lower_conds::tests::' --quiet
11 passed; 0 failed; 4,694 filtered out
```

Filtered tests were not executed.

## Release fixture checkpoint

A clean detached worktree at exact commit `7b1d072a` was release-built. The
build guard reported fresh with native SHA-256
`ae2bc8c37ad38aaf5ba2d99e0cba9ef72eda94e5125c93b1dbc2a26f0e810ffa`.

The directly adjacent one-arm select fixture remains green across its complete
GCC/Clang O0/O2 family:

```text
uv run python tools/dectest.py \
  '189_effectful_select:*:*:se189_select_one_arm'
SCOPED: 4 lanes of 838 (0%) - no regressions in scope
```

This fixture check proves the owning select family did not regress. The
observed-red AST/render contract is the direct evidence for the newly enabled
origin-wrapped path; no parent fixture A/B was claimed.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the non-exhaustive WP3 renderer and transformation audit. Preserve
the eager-evaluation refusal rules while making only semantic pattern matching
transparent to provenance carriers.
