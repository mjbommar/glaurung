# WP3 AAPCS proof expression origins

Commit `bf8718e9` closes two residual raw-expression readers in ARM/AAPCS call
recovery: locked call targets and the exact outgoing stack-area address.

Provenance around a named `memset`/hard-float callee no longer hides its locked
catalog contract. Provenance around `sp` or `[sp + offset]` likewise no longer
prevents a complete four-byte stack suffix from joining its source-ordered call
layout. Value expressions retain their own and their supplying store's owners;
address ownership remains attached to the address rather than being
misattributed to the value.

The proof boundaries are unchanged: unknown/indirect callees receive no locked
contract; variadic, wide, and unrepresentable catalog layouts refuse; stack
slots still require exact `sp` storage, four-byte width, a complete contiguous
nonnegative range, and no intervening clobber or control boundary.

Two strengthened contracts were observed red before repair: attributed named
targets returned no known ARM layout, and attributed stack addresses caused the
complete stack-area candidate to refuse. After repair:

```text
cargo test --features python-ext --lib \
  ir::call_args::aapcs::tests::attributed_calls_retain_their_locked_aapcs_contracts --quiet
1 passed

cargo test --features python-ext --lib \
  ir::call_args::aapcs::tests::attributed_aapcs_stack_area_is_recognized --quiet
1 passed

cargo test --features python-ext --lib ir::call_args::aapcs::tests --quiet
6 passed
```

An exact detached release build of `bf8718e9` was fresh. The focused
`call_into_spill` comparison produced:

```text
armv7 O0:     fail
armv7 O2:     pass
armv7_a32 O0: pass
armv7_a32 O2: pass
```

The ARMv7 O0 cell is currently reported as a baseline regression and emits an
uninitialized frame-slot read for source parameter `a1`. An exact clean release
build of parent `9ab2e802` produces the same output and failure, proving it is
not introduced by this commit. That real defect remains in the ARM
stack/storage lane.

Both dedicated real mixed hard-float call tests pass. The periodic canonical
Hello checkpoint also passes exactly six GCC symbols/PIE cells: O0 and O2 on
x86-64, AArch64, and ARMv7. No broad Rust, Python, fixture, DecBench, or Joern
suite ran.

This closes these bounded AAPCS expression readers, not WP3. Universal
production attribution, explicit invalidation, and remaining expression
consumers stay open.
