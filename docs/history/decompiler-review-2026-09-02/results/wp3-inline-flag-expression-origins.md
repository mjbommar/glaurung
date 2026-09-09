# WP3 inline-flag expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `a50e583f` makes both shared inline-flag comparison lookups transparent
to expression-origin carriers on the comparison definition. A proven reaching
`flag = (value == 0)` can therefore still become the source-like branch
condition after attribution, rather than leaving the opaque `if (flag)` form.

The comparison expression keeps its exact owner when moved. The removed
definition statement owner is deterministically unioned with the surviving
branch owner. Existing barriers remain unchanged: intervening reads, changed
condition inputs, unsafe memory movement, and versioned predicates with
possible successor uses still decline or retain their definition as before.

This is a bounded WP3 expression-consumer migration. It does not complete
universal expression attribution, whole-function DCE migration, or WP3.

## Focused verification

`inline_flag_hoist_sees_attributed_comparison_definition` was observed red
first: the attributed comparison was not recognized, leaving two statements
and an opaque flag condition. After the repair it passes and asserts the exact
expression and statement origin sets.

```text
cargo test --features python-ext --lib \
  ir::ast::lower_conds::tests::inline_flag_hoist_sees_attributed_comparison_definition \
  -- --exact
1 passed; 0 failed; 4,705 filtered out

cargo test --features python-ext --lib \
  'ir::ast::lower_conds::tests::' --quiet
12 passed; 0 failed; 4,694 filtered out
```

Filtered tests were not executed.

## Release fixture checkpoint

A clean detached worktree at exact commit `a50e583f` was release-built. The
build guard reported fresh with native SHA-256
`9d0fb027dee53ed829de7795a5c723b4fb549a9764b6940dd42e1943f02853b1`.

The directly owning polarity canary remains green across its four compiler and
optimization lanes:

```text
uv run python tools/dectest.py @polarity
SCOPED: 4 lanes of 838 (0%) - no regressions in scope
```

The observed-red unit contract proves the newly enabled attributed-definition
path. The fixture result is a focused predicate-hoisting/inversion
non-regression check; no parent fixture A/B was claimed.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the remaining raw condition consumer audit. Treat attributed select
conditions and attributed branch shells as separate reconstruction boundaries
because their carriers must survive rebuilding, rather than applying a broad
wrapper-stripping rewrite.
