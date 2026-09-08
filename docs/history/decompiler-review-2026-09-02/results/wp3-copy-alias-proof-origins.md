# WP3 copy-propagation alias proofs through origins

Commit `b5cde5e3` makes the existing, fail-closed alias proofs transparent to
`Expr::Origin` carriers. Constant-offset frame slots and image-address forms
remain provable when provenance wraps the address or its constant operands;
indexed, overlapping, or otherwise unproved addresses still decline to fold.

## Focused evidence

The new regression was observed red before the production change: provenance
hid two disjoint constant frame offsets, so the pending load was not folded.

```text
cargo test --features python-ext --lib \
  ir::copy_prop::tests::attributed_disjoint_frame_slots_still_fold_the_pending_load \
  -- --exact

1 passed; 0 failed; 4,387 filtered out; test body 0.00s
```

The complete touched module then passed:

```text
cargo test --features python-ext --lib ir::copy_prop::

58 passed; 0 failed; 4,330 filtered out; test bodies 0.00s
```

No fixture matrix, full Rust/Python suite, DecBench, or Joern run was used for
this bounded increment.
