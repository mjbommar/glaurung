# WP3 loop-entry source expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `2644823c` makes loop-entry carrier coalescing recognize an attributed
register source. When that redundant entry copy is deleted, both its statement
owner and source-expression owner are transferred to the surviving loop.

Typed source evidence, dead-source proof, coalescible value roles, no protected
identity, and the existing whole-function goto refusal remain mandatory. This
is a bounded WP3 migration, not completion of the package.

## Focused verification

The existing immediately-entered-loop fixture now attributes the deleted entry
copy and its source register independently and requires both owners on the
surviving loop. It was observed red first because the attributed source left
four statements instead of removing the copy. After repair:

```text
cargo test --features python-ext --lib \
  ir::latch_predicate::tests::coalesces_dead_source_identity_with_immediately_entered_loop_carrier \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::latch_predicate::tests::'
12 passed; 0 failed; 4,366 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
