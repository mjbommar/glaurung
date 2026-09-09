# WP3 cdecl32 proof expression origins

Commit `e5fe6588` closes two residual raw-expression readers in the cdecl32
argument folder: outgoing stack-slot classification and caller-cleanup proof.

An instruction owner around `[esp + offset]` no longer prevents a positive,
nonzero store from becoming a source argument. Likewise, independent origins
on `esp + bytes`, its stack-register operand, and its positive constant no
longer hide the caller-owned cleanup that safely bounds a backward scan across
PIC value normalization. The adjacent entry-frame assignment check also reads
its source register semantically.

The existing proof boundaries are unchanged. Addresses must still use an exact
`esp`/`rsp` storage identity, have no index, and use a nonnegative displacement;
stores must be nonzero width. Cleanup must still be an adjacent positive add
back into the same stack identity, and the scan remains bounded. Address and
cleanup owners stay on their original statements; only the value expression
and consumed store owner are unioned onto a recovered argument.

Two strengthened contracts were observed red before repair. The attributed
stack address left both stores unfolded, while the attributed cleanup failed to
authorize scanning across the PIC GOT copy and produced a zero-argument call.
After repair:

```text
cargo test --features python-ext --lib \
  ir::call_args::tests::cdecl32_folds_attributed_stack_stores_into_the_call_owner --quiet
1 passed

cargo test --features python-ext --lib \
  ir::call_args::tests::cdecl32_steps_over_the_pic_got_copy_before_a_call --quiet
1 passed

cargo test --features python-ext --lib cdecl32_ --quiet
28 passed
```

An exact detached release build of `e5fe6588` was fresh. Six i386 fixture
functions pass at O0/O2 with no regression in scope:

```text
06_calling_conventions:i386:{O0,O2}:{forward_sum6,tailcall_to_sum4}
4 passed

11_call_shapes:i386:{O0,O2}:call_into_spill
2 passed
```

The periodic six-cell Hello checkpoint passed on the immediately preceding
source increment, so it was not repeated. No broad Rust, Python, fixture,
DecBench, or Joern suite ran.

This completes these bounded cdecl32 proof readers, not WP3. Universal
production attribution, explicit invalidation, and remaining expression
consumers stay open.
