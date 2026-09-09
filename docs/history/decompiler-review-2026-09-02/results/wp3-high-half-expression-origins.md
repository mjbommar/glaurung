# WP3 high-half expression origins

Commit `b3110f25` closes the high-half and wide-mask consumer in scored-C ABI
width refinement.

The recursive high-half scan now reads expression meaning through provenance
carriers. An attributed shift count of at least 32 bytes no longer hides the
fact that its left operand needs a complete 64-bit SysV eightbyte, and an
attributed constant mask wider than 32 bits likewise widens the value it
constrains. The same local visitors now cover numeric conversions, dereferences,
function-table indices, expression calls, selects, and wide-arithmetic operands.
Shift-count operands remain excluded from value widening.

The existing packed-argument contract was strengthened so that the shift, its
register and count, and the wide mask each carry independent instruction
origins. It was observed red before the repair:

```c
long packed(int arg0, int arg1)
```

After the repair it retains complete argument and return widths:

```c
long packed(long arg0, long arg1)
```

Focused validation:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::decbench_abi_widths_preserve_high_halves_of_packed_arguments --quiet
1 passed

cargo test --features python-ext --lib high_half --quiet
5 passed

cargo test --features python-ext --lib decbench_abi_ --quiet
7 passed

python tools/dectest.py \
  195_by_value_aggregates:{gcc,clang}:{O0,O2}:bv195_consume_pair --full
4 passed
```

The real fixture retains its recovered `struct bv195_pair p` signature in all
four GCC/Clang O0/O2 lanes and its output continues to read both packed 32-bit
members from the incoming eightbyte. The fixture is therefore a no-regression
control for the same ABI shape; the independently attributed synthetic contract
is the direct proof of this defect.

An exact detached release build of `b3110f25` was fresh. The periodic six-cell
GCC symbols/PIE Hello checkpoint had passed immediately before this narrow
increment at `5e2b7fff`, so it was not repeated. No broad suite ran.

This closes one bounded ABI expression-consumer family, not WP3. Remaining
expression consumers and universal production attribution stay open.
