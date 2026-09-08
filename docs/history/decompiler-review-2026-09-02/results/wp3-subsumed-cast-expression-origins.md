# WP3 subsumed-cast expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `22cb5827` makes the proved equal-or-wider inner-cast fold transparent
to expression-origin carriers. An attributed `castN(castM(x))`, where `M >= N`,
now reduces to `castN(x)` exactly as the bare form does. The surviving cast
owns both cast instructions, while `x` retains its independent subtree origin.

The width proof and narrowing refusal are unchanged. This is one bounded
constant-fold migration, not completion of WP3.

## Focused verification

The three-owner test was observed red first because the inner cast's carrier
blocked recognition. After repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_equal_or_wider_inner_cast_is_subsumed_with_origins \
  -- --exact
1 passed; 0 failed; 4,366 filtered out

cargo test --features python-ext 'ir::const_fold::tests::'
65 passed; 0 failed; 4,302 filtered out
```

The touched-module run includes the narrowing refusal and checked-in
real-binary end-to-end test. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
