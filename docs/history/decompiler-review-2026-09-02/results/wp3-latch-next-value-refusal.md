# WP3 attributed latch next-value refusal

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `c6795d65` makes the latch next-value root query transparent to expression
ownership. An attributed next value that is the saved snapshot therefore still
triggers the existing fail-closed refusal instead of incorrectly deleting the
predicate assignment and rewriting the loop condition.

This strengthens safety rather than enabling a new fold. The function remains
byte-for-byte unchanged when the installed next value aliases the snapshot.
This is a bounded WP3 migration, not completion of the package.

## Focused verification

The new negative regression wraps the installed saved-snapshot register in an
origin carrier and requires the complete input function to remain unchanged. It
was observed red first because the pass incorrectly performed the fold. After
repair:

```text
cargo test --features python-ext --lib \
  ir::latch_predicate::tests::keeps_predicate_when_attributed_next_value_is_the_saved_snapshot \
  -- --exact
1 passed; 0 failed; 4,378 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::latch_predicate::tests::'
13 passed; 0 failed; 4,366 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
