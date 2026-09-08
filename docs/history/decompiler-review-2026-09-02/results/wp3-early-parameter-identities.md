# WP3 early parameter identities

## Outcome

Commit `079e26d5` makes value numbering attach source-parameter ownership
directly to exact version-zero SSA values. The attachment is constrained by the independently
computed live ABI parameter-slot set. A later version of the same physical
register is therefore not a parameter, and an unused ABI argument register is
not promoted merely because of its spelling.

This is the prerequisite for migrating early semantic consumers away from
parsing `argN`. It does not yet switch constant folding. The relevant fold runs
before stack-object promotion, while its current special case is expressed as
`Deref(StackAddr(argN))`; that stage mismatch needs an exact production-shape
test before the old slot authority can be removed safely.

## Focused evidence

```text
cargo test --lib --features python-ext \
  abi_parameter_slots_attach_only_to_live_version_zero_values
1 passed; 4,458 filtered out
```

The test exercises the production value-numbering entry point and proves all
three boundaries in one small function: live `rdi` version zero owns slot 0,
defined `rdi#1` does not, and unused `rsi` does not.

No broad Rust or Python suite, fixture matrix, DecBench, or Joern lane ran.
