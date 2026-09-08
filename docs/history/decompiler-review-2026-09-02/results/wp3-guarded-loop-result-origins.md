# WP3 guarded-loop result origin composition

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `ca3ff99a` makes guarded `do/while` recovery compare the zero-iteration
and final result expressions by semantic value when their ownership carriers
differ. When the entry guard is removed, its return-value owner is transferred
to the surviving final return, which retains the deterministic union of both
contributors.

Different semantic result values still block rotation. The existing entry,
stable-prelude, carried-latch, overwrite, and trailing-control refusals remain
mandatory. This is a bounded WP3/WP4 migration, not completion of either
package.

## Focused verification

The guarded-loop fixture now assigns distinct owners to the removed early
return and surviving final return, and requires their union after recovery. It
was observed red first because the carrier-sensitive comparison left the
six-statement rotated form intact. After repair:

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
