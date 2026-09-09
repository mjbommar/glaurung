# WP3 spilled passthrough parameter recovery

Commit `c41c0b6b` lets function-level prototype refinement carry a recovered
callee parameter type through an exact O0 stack spill/reload. The compiled
forwarding wrapper now emits a pointer parameter and passes it to the local
callee without an invented cast:

```c
int forward_pointer(int *arg0) {
    extern unsigned int read_first(int *);
    return read_first(arg0);
}
```

## Root cause and boundary

Pass diagnostics showed that the AST identity sidecar already projected the
entry `rdi` value to `arg0`. The stale `long` was selected earlier, while
refining the function-level `RecoveredPrototype` from the direct callee's
definition-site contract. Its copy-origin walker handled register assignments
but stopped at this ordinary O0 chain:

```text
store [rbp-8] <- rdi#0
rax#1 = load [rbp-8]
rdi#1 = rax#1
call read_first
```

The repair is deliberately narrower than memory alias analysis. It accepts a
load only when the first preceding memory writer in the same basic block is a
store to the identical `MemOp`, and that store reads a register SSA value. A
different slot, any intervening store or conditional store, a call, an
intrinsic, or an unknown operation makes the proof fail closed. Cross-block
reaching stores remain unsupported until authoritative MemorySSA owns them.

Hardening commit `cbdf4f06` closes a second alias boundary exposed immediately
after the first increment. Equal `MemOp` spelling does not prove equal storage
when its base register is redefined between the store and load. The proof now
requires the same exact SSA base identity and accepts only non-indexed,
non-segmented frame/stack-relative addresses. Arbitrary global, TLS, indexed,
and renamed-base loads decline rather than borrowing a parameter type.

## Focused evidence

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`.

```text
cargo test --features python-ext \
  python_bindings::ir::callee_contracts::tests::exact_same_block_spill_reload_refines_passthrough_parameter \
  -- --exact --nocapture
1 passed; 0 failed

cargo test --features python-ext \
  python_bindings::ir::callee_contracts::tests::intervening_memory_writer_blocks_spill_passthrough_refinement \
  -- --exact --nocapture
1 passed; 0 failed

cargo test --features python-ext \
  python_bindings::ir::callee_contracts::tests::different_spill_slot_blocks_passthrough_refinement \
  -- --exact --nocapture
1 passed; 0 failed

cargo test --features python-ext --lib \
  python_bindings::ir::callee_contracts::tests::redefined_address_base_blocks_spill_passthrough_refinement \
  -- --exact --nocapture
RED: pointer refinement incorrectly survived the base redefinition

cargo test --features python-ext --lib \
  python_bindings::ir::callee_contracts::tests -- --nocapture
GREEN: 10 passed; 0 failed

uv run maturin develop --release
finished release profile; editable wheel installed

uv run pytest \
  python/tests/test_decompiler_fixture_harness.py::test_real_direct_callee_pointer_type_refines_forwarding_caller_parameter \
  -q -x
1 passed
```

The first real-fixture run after the code repair produced the correct C but
exposed a stale assertion expecting `int * arg0`; the renderer's established
canonical spelling is `int *arg0`, so the fixture assertion was corrected and
rerun green. No broad fixture or test sweep was run.
