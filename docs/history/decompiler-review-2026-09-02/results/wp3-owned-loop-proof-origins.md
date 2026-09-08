# WP3 owned-loop proof origin transparency

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `c4e3f4b3` makes the entry-owned loop proof compare alias-resolved entry
and latch predicates without their ownership carriers. Attributed but
semantically identical predicates can therefore recover a head-tested `while`
instead of remaining a rotated `do/while` solely because their source
locations differ.

The proof normalization is private to the equality check. The retained outer
guard and the original attributed latch predicate remain in the output, and
the existing no-else, stable-prelude, alias-depth, and overwrite refusals are
unchanged. This is a bounded WP3/WP4 migration, not completion of either
package.

## Focused verification

The existing coalesced-cursor fixture now attributes the entry predicate,
latch predicate, their operands, and the alias source independently. It was
observed red first because provenance blocked the recovery. After repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::an_entry_owned_coalesced_cursor_recovers_a_head_tested_loop \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
