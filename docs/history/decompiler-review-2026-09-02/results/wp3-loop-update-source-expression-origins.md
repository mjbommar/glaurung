# WP3 loop-update source expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `e8dab427` makes typed source-loop update coalescing recognize an
attributed scratch-to-carrier source. When that redundant tail assignment is
deleted, both its statement owner and source-expression owner are transferred
to the surviving loop.

Protected source identity, compatible semantic types, exact value width,
single scratch definition, no suffix use, and no conflicting old-carrier read
remain mandatory. This is a bounded WP3 migration, not completion of the
package.

## Focused verification

The existing typed source-update fixture now attributes the deleted tail
assignment and its register source independently and requires both owners on
the surviving loop. It was observed red first because the attributed source
left the scratch variable in rendered output. After repair:

```text
cargo test --features python-ext --lib \
  ir::latch_predicate::tests::coalesces_a_typed_loop_update_scratch_into_its_source_carrier \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::latch_predicate::tests::'
12 passed; 0 failed; 4,366 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
