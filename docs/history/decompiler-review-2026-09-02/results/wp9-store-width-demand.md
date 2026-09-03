# WP9 store-width bit-demand evidence

Date: 2026-09-03

## Defect

`141_atomics:clang:O0:atomic_flag_round_trip` rendered a read of `ret` before
its first definition. Clang's byte exchange is lifted as the semantically exact
x86 parent-register update:

```text
rax = rax & -256
rax = rax | low_byte
store[1] address <- al
```

Target-aware SSA correctly resolves `al` to the current `rax` storage value.
The bit-demand oracle, however, treated every operand of an observable store as
a 64-bit demand. That falsely made the preserved upper 56 bits observable and
kept the entry `rax` value alive as an invented C local.

## Change

`src/ir/definedness.rs` now seeds the source of a register-valued `Store` or
`CondStore` with exactly the store width. Address registers and conditional
predicates remain whole-value demands. Zero or oversized widths fail closed to
a whole-value demand.

This rule is machine- and container-independent: it follows LLIR memory-store
semantics after a target-specific lifter has produced the operation. It does
not add an x86 exception or fabricate an initializer.

## TDD and validation

The focused RED test models the x86-64 parent-register update followed by a
one-byte store from `al`. Before the production change, the preserved input
was demanded as `0xffff_ffff_ffff_ff00`; afterward its demand is zero and the
existing proof-directed rewrite replaces only that dead masked input.

```text
cargo test --features python-ext --lib ir::definedness::tests
6 passed; 0 failed

tools/dectest.py \
  141_atomics:clang:O0:atomic_flag_round_trip \
  141_atomics:clang:O2:atomic_flag_round_trip \
  141_atomics:gcc:O0:atomic_flag_round_trip \
  141_atomics:gcc:O2:atomic_flag_round_trip --full --show

clang O0 pass
clang O2 pass
gcc O0   pass
gcc O2   fail (pre-existing baseline state)
SCOPED: 4 lanes of 838 - no regressions in scope
```

A fresh release extension produced no `GLAURUNG_VERIFY_DEFS` finding for either
Clang function. A direct narrow call to the definition-health census returned
an empty violation list for both `141_atomics:clang:O0` and
`141_atomics:clang:O2`. In O0, the first two byte exchanges now begin from a
proof-derived zero value instead of an undefined `ret`; the later full-parent
dependency is retained where it remains observable.

## Limits

This closes the two atomic findings from the 2026-09-03 definition-health
census (`ret` at Clang O0 and `var2` at Clang O2). It does not resolve the
existing GCC O2 semantic failure or the broader exception/Rust definition
families. The def-use baseline must not be refreshed until the other new
findings and the missing lane are resolved or explicitly reviewed.
