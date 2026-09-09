# WP3 flag-condition expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `c16a9a36` completes the branch-condition half of the bounded inline-flag
hoist audit. One semantic classifier now recognizes bare flag, negated flag,
and `flag == 0` forms through expression-origin carriers. The hoist rebuilds
the source comparison while deterministically unioning its owner with the
original condition owner.

This replaces three raw destructuring branches with one carrier-transparent
path and reduces the implementation by 15 lines. Unsupported condition shapes
still pass through byte-for-byte, while reaching-definition, intervening-use,
movement-safety, and versioned-predicate boundaries remain unchanged.

This is a bounded WP3 expression-consumer migration. Attributed select
conditions remain a separate mutation boundary; universal expression
attribution and WP3 remain open.

## Focused verification

The existing inline-flag ownership contract was extended so the consumed flag
condition itself carries a disjoint origin. It asserts that the surviving
comparison receives the exact comparison-plus-condition union, while the
surviving branch statement receives the comparison-definition-plus-branch
union.

```text
cargo test --features python-ext --lib \
  ir::ast::lower_conds::tests::inline_flag_hoist_sees_attributed_comparison_definition \
  -- --exact
1 passed; 0 failed; 4,705 filtered out

cargo test --features python-ext --lib \
  'ir::ast::lower_conds::tests::' --quiet
12 passed; 0 failed; 4,694 filtered out
```

The attributed comparison-definition behavior was observed red in the prior
increment. This condition-carrier extension was validated directly after the
refactor; no separate parent-red execution is claimed. Filtered tests were not
executed.

## Release fixture checkpoint

A clean detached worktree at exact commit `c16a9a36` was release-built. The
build guard reported fresh with native SHA-256
`204381a79d2b47a2c3b4ccd0e12824e5940e2dab50391a959d8e69e38a3dc440`.

```text
uv run python tools/dectest.py @polarity
SCOPED: 4 lanes of 838 (0%) - no regressions in scope
```

The four-lane polarity family is the directly adjacent guard-hoisting and
inversion canary. This is focused non-regression evidence; no parent fixture
A/B or broader quality claim is implied.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Complete the adjacent attributed-select-condition path by mutating only the
semantic condition and composing owners on the replacement. Do not strip the
outer select carrier or weaken arm-use safety checks.
