# WP3 loop-exit copy origin transparency

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `f7a3afe9` makes loop-exit value seeding recognize an attributed header
register copy and compare differently attributed tail values by semantic value.
The header assignment is moved intact before the loop and both tail assignments
remain intact, so every existing expression owner survives without transfer.

The header must still be an exact register copy, the two tail values must still
be semantically identical and stable, and dependency-write and control-bypass
refusals remain mandatory. This is a bounded WP3/WP4 migration, not completion
of either package.

## Focused verification

The existing exit-value fixture now attributes its header copy and gives its
two semantically equal tail values different owners. It was observed red first
because the carrier prevented seeding. After repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::exit_value_copy_is_seeded_before_a_head_tested_loop \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
