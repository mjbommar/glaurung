# WP3 copy propagation preserves attributed indirect stores

Commit `7c60441e` closes an lvalue-category correctness hole in copy
propagation. When a pointer scratch copied an attributed promoted-local value,
the store-address substitution previously failed to recognize the semantic
register and collapsed an explicit `Lea` address into a bare promoted local.
That changed `*pointer = value` into `local = value`.

The repaired boundary recognizes the copied register through its origin
carrier, retains the explicit indirect-address container, and transfers the
copied expression's owner to that surviving address. The existing refusal for
a bare ambiguous store address is likewise origin-transparent.

## Focused evidence

The end-to-end regression was observed red before the production change. The
failure showed the store address had become `Origin(Reg("local_20"))` instead
of remaining an `Lea`.

```text
cargo test --features python-ext --lib \
  ir::copy_prop::tests::an_attributed_pointer_scratch_store_stays_indirect \
  -- --exact

1 passed; 0 failed; 4,388 filtered out; test body 0.00s
```

The complete touched module then passed:

```text
cargo test --features python-ext --lib ir::copy_prop::

59 passed; 0 failed; 4,330 filtered out; test bodies 0.00s
```

No fixture matrix, full Rust/Python suite, DecBench, or Joern run was used for
this bounded increment.
