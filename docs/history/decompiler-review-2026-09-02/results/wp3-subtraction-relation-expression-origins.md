# WP3 subtraction-relation expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `6c737361` makes subtraction zero-test recovery transparent to
expression-origin carriers. Attributed `(x - y) == 0` and `!= 0` forms recover
the same readable `x == y` or `x != y` relation as bare expressions. The
surviving relation owns the deterministic union of the outer comparison and
the consumed subtraction or attributed zero contributors.

The fold remains restricted to equality and inequality against exact zero;
its modular-machine-arithmetic proof and refusal surface are unchanged. This
is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The attributed subtraction test was observed red first because the carrier
blocked recognition and left `(x - y) == 0` in the AST. After repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_subtraction_zero_test_recovers_relation_and_unions_origins \
  -- --exact
1 passed; 0 failed; 4,362 filtered out

cargo test --features python-ext 'ir::const_fold::tests::'
61 passed; 0 failed; 4,302 filtered out
```

The touched-module run includes its existing checked-in real-binary
end-to-end test. No full Rust, Python, fixture, architecture, DecBench, or
Joern suite was run.

## Next boundary

Continue one independently proved constant-fold constructor family at a time,
preserving existing recognition/refusal proofs and composing only consumed
semantic origins.
