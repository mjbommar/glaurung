# WP3 relation-source expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `af0c014b` makes terminal mixed-view relation recovery compare the
unsigned-equality and signed-less source values through their origin carriers.
Semantically identical sources now recover the readable `K < signed(x)` form
even when each machine view came from a differently attributed instruction.
Both source owners are retained on the recovered relation.

Width, signedness, constant equality, and representability proofs remain
mandatory. This is one bounded wildcard-consumer migration, not completion of
WP3.

## Focused verification

The strengthened terminal-relation test was observed red first because raw
source equality treated distinct carriers as distinct values. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_terminal_mixed_view_relation_unions_consumed_origins \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
76 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
