# WP3 pointer-access expression origins

Commit `5e2b7fff` closes the recursive pointer-access-width consumer in the
scored-C ABI refinement pass.

The walker and direct-base classifier now inspect semantic expressions, descend
through origin carriers, numeric conversions, expression calls, function-table
indices, and wide-arithmetic arguments, and classify attributed operands of an
additive address. The promoted-local store exclusion is also origin-transparent,
so writing a scalar local cannot masquerade as a pointer dereference merely
because the address carries provenance.

The strengthened byte-access contract attributed both the dereference and its
scaled address. It was observed red before the repair: a sole one-byte access
left `arg0` at the stale `int *` pointee width instead of refining it to
`char *`. After the repair, that contract and the attributed promoted-local
negative control pass.

Focused validation:

```text
two exact pointer-refinement contracts: 2 passed
cargo test --features python-ext --lib decbench_abi_ --quiet
7 passed

python tools/dectest.py \
  '207_scaled_index_addressing:*:*:byte_stride_unscaled' --jobs 4 --full
GCC O0/O2: pass; Clang O0: pass; Clang O2: known fail; no regression
```

Direct inspection of the passing GCC-O0 cell confirms a `const uint8_t *bytes`
parameter and `bytes[i]` access. The Clang-O2 cell retains its pre-existing
vectorized-loop failure with unresolved vector values; this increment neither
caused nor closes that separate WP6/WP9 capability gap.

An exact detached release build of `5e2b7fff` was fresh. The periodic GCC
symbols/PIE Hello checkpoint passed all six O0/O2 cells across x86-64, AArch64,
and ARMv7. No broad suite ran.

This closes one bounded ABI expression-consumer family, not WP3. Remaining
expression consumers and universal production attribution stay open.
