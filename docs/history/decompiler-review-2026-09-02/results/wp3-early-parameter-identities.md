# WP3 early parameter identities

## Outcome

Commit `079e26d5` makes value numbering attach source-parameter ownership
directly to exact version-zero SSA values. The attachment is constrained by
the independently computed live ABI parameter-slot set. A later version of the same physical
register is therefore not a parameter, and an unused ABI argument register is
not promoted merely because of its spelling.

Commit `86a3b39a` completes the bounded consumer migration. Because cdecl
parameters are stack-based rather than register-based, pipeline-owned stack
slots are projected into the same typed sidecar before the early fold. The
production pipeline now calls the identity-aware folder, and the former
slot-authority path that parsed `argN` has been deleted. An unowned `arg99`
therefore refuses while an explicitly owned `arg0` retains the established
full-width load fold.

## Focused evidence

```text
cargo test --lib --features python-ext \
  abi_parameter_slots_attach_only_to_live_version_zero_values
1 passed; 4,458 filtered out

cargo test --lib --features python-ext \
  stack_parameter_projection_records_only_owned_slots
1 passed; 4,460 filtered out

cargo test --lib --features python-ext \
  early_constant_fold_uses_typed_stack_parameter_roles
1 passed; 4,460 filtered out

cargo test --lib --features python-ext \
  parameter_address_load_requires_a_typed_parameter_role
1 passed; 4,460 filtered out

uv run maturin develop
success

uv run pytest \
  python/tests/test_pe32_cdecl_roundtrip.py::test_i386_optimized_cdecl_stack_arguments_round_trip \
  -q
1 passed
```

The test exercises the production value-numbering entry point and proves all
three boundaries in one small function: live `rdi` version zero owns slot 0,
defined `rdi#1` does not, and unused `rsi` does not. The two new migration
tests were observed RED as missing APIs before the implementation was added.

The two other tests in `test_pe32_cdecl_roundtrip.py` are red at this checkout:
the PE32 sample renders `_main(void)`, and the unoptimized generated call keeps
redundant `(int)` casts. A one-line A/B rebuild with the old slot-authority
caller produced the same two failures and the same output, so neither is caused
by this migration. They remain separate pre-existing correctness work.

No broad Rust or Python suite, fixture matrix, DecBench, or Joern lane ran.
