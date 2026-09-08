# WP3 guarded-loop seed origin composition

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `a4326607` makes guarded `do/while` recovery compare the entry value and
surviving current seed by semantic value when their ownership carriers differ.
When the entry guard is removed, its value owner is transferred to the
surviving seed expression, which retains the deterministic union of both
contributors.

The exact current assignment must still exist, and the existing stable-value,
carried-latch, result-overwrite, and trailing-control refusals remain
mandatory. This is a bounded WP3/WP4 migration, not completion of either
package.

## Focused verification

The guarded-loop fixture now assigns distinct owners to the entry value and
surviving `current = arg0` seed and requires their union after recovery. It was
observed red first because the carrier-sensitive comparison left the rotated
form intact. After repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::guarded_do_while_rotates_back_to_pre_tested_while \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
