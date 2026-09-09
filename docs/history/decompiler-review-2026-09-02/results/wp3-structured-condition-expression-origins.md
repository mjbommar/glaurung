# WP3 structured-condition expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `d8e6c351` closes the structured-condition adoption boundary identified
after the inline-flag audit. An origin carrier around a plain flag condition no
longer makes that flag look like a finished comparison. The structurer now sees
through the carrier, consumes the dead reaching flag definition, and recovers
the comparison used by the rebuilt `if` or `while`.

Ownership remains compositional: the comparison and original condition owners
are unioned on the recovered expression, while the removed definition-statement
owner joins the branch-statement owner returned to the region builder. An
already-hoisted attributed comparison or attributed negated comparison is still
adopted unchanged.

This is a bounded WP3 consumer migration. It does not complete authoritative
identity persistence, universal expression attribution, or WP3.

## Observed-red and focused verification

`structured_condition_hoist_sees_attributed_flag_and_preserves_owners` was
observed red first: the flag assignment remained in the structured body because
the attributed `Reg` condition was classified as a nontrivial expression. The
repair makes that exact contract green and checks the expression and statement
owner unions independently.

```text
cargo test --features python-ext --lib \
  ir::ast::lower_conds::tests::structured_condition_hoist_sees_attributed_flag_and_preserves_owners \
  -- --exact
1 passed; 0 failed; 4,707 filtered out

cargo test --features python-ext --lib \
  'ir::ast::lower_conds::tests::'
14 passed; 0 failed; 4,694 filtered out
```

Filtered tests were not executed.

## Release fixture checkpoint

A clean detached worktree at exact commit `d8e6c351` was release-built. The
build guard reported fresh with native SHA-256
`7180859c4cf316a836c01c232c409481659774d1ec2b0101dd3d880aaef14ac9`.

```text
uv run python tools/dectest.py @polarity
SCOPED: 4 lanes of 838 (0%) - no regressions in scope
```

The four-lane polarity family is the directly adjacent condition-recovery
canary. This is focused non-regression evidence, not a broad quality or
architecture claim. No full Rust, Python, fixture, architecture, DecBench, or
Joern suite was run.

## Next boundary

Continue the bounded WP3 audit outside `lower_conds.rs`: find the next raw
expression consumer that mistakes an origin carrier for semantic structure,
add one observed-red ownership contract, and validate only its owning module
and smallest real fixture family.
