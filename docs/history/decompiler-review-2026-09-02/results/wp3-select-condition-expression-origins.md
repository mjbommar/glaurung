# WP3 select-condition expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `77839599` completes the select-condition half of the bounded inline-
flag hoist audit. An attributed select containing an independently attributed
flag condition now receives the proven reaching comparison without removing
or flattening either carrier.

Only the semantic condition is replaced. The comparison and original
condition owners are unioned on that replacement; the outer select keeps its
own owner; and the removed comparison-definition statement owner joins the
surviving assignment statement. Select arms remain untouched. Negated flag
forms use the shared origin-transparent comparison negation introduced in the
preceding increment.

Existing refusal rules remain unchanged: a select arm reading the flag, an
intervening use, unsafe condition movement, or a missing comparison definition
still prevents the rewrite.

This is a bounded WP3 expression-consumer migration. It does not complete
universal production attribution or WP3.

## Focused verification

`inline_flag_hoist_preserves_attributed_select_and_condition` was observed red
first: both statements remained because the outer attributed select was not
recognized. After the repair it passes and asserts four disjoint ownership
facts: comparison, condition, select, and assignment.

```text
cargo test --features python-ext --lib \
  ir::ast::lower_conds::tests::inline_flag_hoist_preserves_attributed_select_and_condition \
  -- --exact
1 passed; 0 failed; 4,706 filtered out

cargo test --features python-ext --lib \
  'ir::ast::lower_conds::tests::' --quiet
13 passed; 0 failed; 4,694 filtered out
```

Filtered tests were not executed.

## Release fixture checkpoint

A clean detached worktree at exact commit `77839599` was release-built. The
build guard reported fresh with native SHA-256
`42902c572e096b44f9273daf5ea59f8ea02e535fa671e30c6bddde9dd73f4d45`.

The directly adjacent pure and one-arm select functions remain green across
their complete GCC/Clang O0/O2 family:

```text
uv run python tools/dectest.py \
  '189_effectful_select:*:*:se189_select_pure' \
  '189_effectful_select:*:*:se189_select_one_arm'
SCOPED: 4 lanes of 838 (0%) - no regressions in scope
```

Those four lanes contain eight selected function verdicts. The observed-red
unit contract proves the attributed-select path; the fixture run is focused
non-regression evidence rather than a parent/tip quality delta.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Re-audit the remaining raw condition matchers in `lower_conds.rs`, especially
structured-condition adoption and nested negated comparisons. Keep each
carrier attached to the semantic node it owns rather than promoting all
expression origins to statement origins.
