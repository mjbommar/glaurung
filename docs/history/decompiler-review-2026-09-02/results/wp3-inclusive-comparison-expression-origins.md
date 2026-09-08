# WP3 inclusive-comparison expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `97aef0c3` makes the existing inclusive-comparison fold transparent to
expression-origin carriers. Attributed machine comparisons of the form
`(x == y) | (x < y)` now recover the same signed or unsigned `x <= y` relation
as bare comparisons, and the surviving comparison receives the deterministic
union of both contributing instruction-origin sets.

The operand-equality, signedness, and accepted-comparison checks are unchanged.
This is one bounded constant-fold migration; it does not complete universal
expression attribution or the wider WP3 constant-fold migration.

## Focused verification

The new attributed-comparison test was observed red first: the origin wrappers
prevented recognition, leaving the raw `Eq | Slt` tree in output. After the
repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_equality_or_less_merges_and_unions_origins \
  -- --exact
1 passed; 0 failed; 4,360 filtered out

cargo test --features python-ext 'ir::const_fold::tests::'
59 passed; 0 failed; 4,302 filtered out
```

The touched-module run includes its existing checked-in real-binary
end-to-end test. No full Rust, Python, fixture, architecture, DecBench, or
Joern suite was run.

## Next boundary

Continue the constant-fold constructor audit one independently proved rewrite
family at a time. A synthesized relation must see transparent carriers and
must union every consumed semantic contributor without weakening its existing
width, signedness, or refusal proof.
