# WP3 switch-condition expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `93de6232` makes GCC comparison-ladder recognition transparent to
expression-origin carriers on conditions, comparison operands, nested signed
and unsigned machine views, and lifted greater-than flag identities. Adding
instruction provenance to an otherwise valid ladder no longer prevents its
recovery as a structured `switch`.

The synthesized switch now also includes each consumed condition's owner in
its deterministic statement-origin union. Existing single-discriminant,
signed-range, reachability, and control-flow refusal rules remain unchanged.
This is one bounded wildcard-consumer migration spanning WP3 and WP5, not
completion of either package.

## Focused verification

The existing attributed GCC-ladder test was strengthened to attribute every
condition and include those owners in the expected switch union. It was
observed red first because the raw condition matcher rejected the carrier.
After repair:

```text
cargo test --features python-ext --lib \
  ir::switch_ladder::tests::an_attributed_gcc_comparison_ladder_becomes_an_attributed_switch \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::switch_ladder::tests::'
28 passed; 0 failed; 4,350 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
