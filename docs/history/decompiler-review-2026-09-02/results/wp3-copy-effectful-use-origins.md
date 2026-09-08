# WP3 attributed adjacent effectful uses

Commit `129a5277` makes the adjacent effectful-value mover recognize an
attributed direct register use. A one-use call temporary can therefore still
move into its immediate assignment or promoted-local store consumer instead of
remaining as artificial output solely because provenance is present.

The call remains evaluated exactly once. Its expression receives the canonical
union of the deleted definition statement and consumed use-expression owners;
the surviving statement independently receives the definition/consumer union.
The existing adjacency, one-read, direct-use, and store-sequencing refusals are
unchanged.

## Focused evidence

The regression was observed red before the production change: the attributed
consumer register prevented the call temporary from moving at all.

```text
cargo test --features python-ext --lib \
  ir::copy_prop::adjacent::tests::attributed_effectful_use_moves_with_a_canonical_origin_union \
  -- --exact

1 passed; 0 failed; 4,391 filtered out; test body 0.00s
```

The complete touched submodule then passed:

```text
cargo test --features python-ext --lib ir::copy_prop::adjacent::

21 passed; 0 failed; 4,371 filtered out; test bodies 0.00s
```

No fixture matrix, full Rust/Python suite, DecBench, or Joern run was used for
this bounded increment.
