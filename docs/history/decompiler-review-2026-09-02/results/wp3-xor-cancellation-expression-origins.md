# WP3 XOR-cancellation expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `072412ce` makes one-level associative XOR cancellation transparent to
expression origin carriers. Separately attributed copies of the same semantic
flag now cancel through an attributed nested XOR. The recovered surviving
relation retains both repeated-flag owners, the nested-XOR owner, its own
owner, and the enclosing operation owner.

This is the common x86 `SF ^ (relation ^ SF)` cleanup shape. It is one bounded
constant-fold migration, not completion of WP3.

## Focused verification

The five-owner signed-condition test was observed red first because carrier
identity blocked both nested-shape recognition and repeated-flag equality.
After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_xor_cancellation_unions_consumed_flag_origins \
  -- --exact
1 passed; 0 failed; 4,375 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
74 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed. The touched-module run includes the existing
XOR, signed-condition, origin, refusal, and checked-in real-binary controls. No
full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.
