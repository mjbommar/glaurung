# WP3 wide-copy rendering through expression carriers

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `c08b6dd9` makes the DecBench renderer recognize complete 16-byte loads
and stores through `Expr::Origin`. Wide locals therefore stay byte arrays and
attributed transports retain the same `__builtin_memcpy`/`__builtin_memmove`
spelling as identical plain expressions. Only the provenance carrier is
transparent; the underlying dereference width, wide-local classification, and
load-before-store ordering proofs are unchanged.

## Observed-red and focused verification

`attributed_sixteen_byte_load_store_keeps_every_byte` was observed red before
the repair. A complete attributed vector transfer rendered as:

```c
unsigned char var0[16] __attribute__((aligned(16)));
var0 = *(long *)(arg1);
*(long *)(arg0) = var0;
```

That both narrowed each 16-byte operation to one machine word and attempted an
invalid C assignment to an array. After the repair it renders the complete
transport:

```c
__builtin_memcpy(var0, (void *)(arg1), 16);
__builtin_memmove((void *)(arg0), var0, 16);
```

The observed-red contract, its plain-expression control, the 16-byte-store
filter, and the address-conversion control all pass:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::attributed_sixteen_byte_load_store_keeps_every_byte -- --exact
cargo test --features python-ext --lib \
  ir::ast::tests::decbench_adjacent_sixteen_byte_load_store_keeps_every_byte -- --exact
cargo test --features python-ext --lib decbench_sixteen_byte --quiet
cargo test --features python-ext --lib \
  decbench_wide_copy_addresses_convert_to_object_pointers --quiet

all commands passed
```

Filtered tests were not executed.

## Exact release checkpoint

A clean detached worktree at exact commit `c08b6dd9` was release-built. The
extension SHA-256 is
`45569201208976fe58436ac431d66c0cc0a36936c057dd6559c2a932a3dc60e4`.
The complete fixture-188 slice remains green across GCC/Clang O0/O2: all 16
selected function cells pass, including the lane-arithmetic negative control.

```text
uv run --no-sync python tools/dectest.py \
  '188_vector_transport:*:*:*' --jobs 4 --full

16 function cells passed; 0 regressions in the four fixture lanes
```

This retained fixture result is not claimed as an attributable corpus-output
improvement. No whole-Python, DecBench, or Joern gate was run for this bounded
increment.

## Next boundary

Continue the render-consumer audit with one raw-expression match at a time.
Wide zero stores, pointer-valued stores, promoted-local destinations, and
aggregate returns still have direct pattern matches; each needs its own
observed-red contract before becoming origin-transparent.
