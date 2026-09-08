# WP3 guarded-loop expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `fca387da` makes guarded `do/while` rotation inspect the entry sentinel
comparison through expression-origin carriers. An attributed null sentinel no
longer leaves the entry `if` plus rotated `do/while`; the source-like pre-tested
`while` is recovered and its condition retains the sentinel owner.

Entry-result equality, stable prelude, carried-latch identity, zero-iteration
result, and trailing-control refusal rules remain unchanged. This is a bounded
WP3/WP4 migration, not completion of either package.

## Focused verification

The guarded-loop fixture now attributes both cloned null sentinels and requires
that owner on the reconstructed `while` bound. It was observed red first because
the raw entry-comparison matcher left six statements instead of five. After
repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::guarded_do_while_rotates_back_to_pre_tested_while \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
