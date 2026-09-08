# WP3 guarded-copy expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `7ff9bdc2` makes the guarded-switch speculation proof transparent to
origin carriers on a total register/constant/cast copy. An attributed compiler
copy between a terminating range guard and its exhaustive switch can remain
hoisted while the redundant guard becomes the switch default.

The copy statement and its complete expression tree remain unchanged in the
output. The proof still rejects loads, calls, arithmetic, memory effects, and
any copy read by the guard. This is a bounded WP3/WP5 migration, not completion
of either package.

## Focused verification

The existing total-copy test now attributes its statement, cast, and source
register. It was observed red first because the raw copy-expression matcher
left the original guard/copy/switch triplet intact. After repair:

```text
cargo test --features python-ext --lib \
  ir::guarded_switch::tests::hoists_a_total_copy_between_terminating_guard_and_switch \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::guarded_switch::tests::'
18 passed; 0 failed; 4,360 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
