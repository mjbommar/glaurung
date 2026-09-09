# WP3 contextual-widening expression origins

Commit `3739f0e3` closes a semantic expression-carrier omission in
`src/ir/widen.rs`.

The widening pass already unwrapped attributed statements, but its recursive
expression rewrite did not descend through `Expr::Origin`. A narrow value with
expression provenance could therefore avoid the explicit zero extension that
preserves the machine's behavior in rebuilt C. The same omission affected the
unsigned reinterpretation required before a logical right shift of a
signed-declared value.

The repair recursively rewrites the owned expression without removing or
reassigning its canonical origin set. It does not broaden the contexts in which
widening is legal, change recovered types, or weaken the existing comparison,
address, and shift-count exclusions.

## Focused evidence

The direct widening test was observed red before the repair: an attributed
signed 32-bit register used by a 64-bit assignment remained a bare register.
After the repair, that test and the attributed logical-shift sibling pass.

```text
cargo test --features python-ext --lib \
  ir::widen::tests::attributed_value_is_widened_without_losing_its_owner \
  -- --exact
1 passed; 4,732 filtered out

cargo test --features python-ext --lib \
  ir::widen::tests::attributed_signed_shift_value_is_reinterpreted_without_losing_its_owner \
  -- --exact
1 passed; 4,732 filtered out

cargo test --features python-ext --lib ir::widen::tests::
25 passed; 4,708 filtered out
```

An exact detached release build of `3739f0e3` passed the build guard with native
SHA-256 `67e3977bc4ea7727ea1108ca3a7e7725ce1adb9dbce3db30a1ad5ae0db95ac2f`.
The directly affected fixture slice passed all eight requested functions:

```text
python tools/dectest.py \
  '02_integer_widths:*:*:mul_widen' \
  '02_integer_widths:*:*:rotr32' --jobs 4 --full --show
GCC/Clang O0/O2: 8 passed; no regression in scope
```

The periodic symbol-bearing Hello checkpoint passed at O0 and O2 on x86-64,
AArch64, and ARMv7. The `-k` expression also selected the corresponding non-PIE
siblings because `pie` is a substring of `nonpie`, so the actual bounded run was
12 passing cells rather than six. This is additional narrow coverage, not a
full Hello matrix.

No broad Rust, Python, fixture, DecBench, or Joern suite ran. This closes one
general expression consumer, not WP3; universal expression attribution and the
remaining identity consumers remain open.
