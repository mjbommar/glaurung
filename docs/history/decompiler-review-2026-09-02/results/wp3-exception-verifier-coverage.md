# WP3 exception verifier coverage

Commit `c2e9e225` closes the pre-render verifier's inconsistent exception-region
coverage. Its read census and flow walker already entered `TryCatch`, but the
whole-function definition census did not. As a result, visibly assigned values
inside recovered try and catch bodies were incorrectly reported as never
defined.

The repair makes each verifier surface recurse consistently through the try
body and every catch: definitions (including the catch binding), unstructured
flow detection, explicit-poison definitions, and dangerous frame-pointer
address scanning. The frame-address scanner also unwraps expression origins and
numeric conversions. This removes false findings without weakening the safety
boundary: poison and provenance-wrapped frame-pointer addresses inside catches
remain findings.

## Focused evidence

The recovered definition contract was observed red first with `local_c` and
`stack_0` reported as `NeverDefined`. At the committed implementation:

```text
cargo test --features python-ext --lib \
  definitions_inside_recovered_exception_regions_are_counted
1 passed; 4,746 filtered out

cargo test --features python-ext --lib \
  poison_inside_a_recovered_catch_remains_a_verifier_finding
1 passed; 4,746 filtered out

cargo test --features python-ext --lib \
  attributed_frame_pointer_address_inside_a_catch_remains_a_finding
1 passed; 4,746 filtered out

cargo test --features python-ext --lib ir::verify_defs::tests::
48 passed; 4,699 filtered out
```

An exact release build of `c2e9e225` produced native SHA-256
`b2d9a822766b838f639c25975b7a3c31af3c1ebc9e8f3c941335a75c7ed4b3ab`.
The exact symbol-bearing GCC-O2 `cpp_exception` specimen now renders with zero
definition-before-use warnings, down from three at its parent. Its output text
is otherwise unchanged from the already-pruned form.

All four GCC/Clang O0/O2 `cpp_exception` execution cells remain green, and the
one real pipeline-profile output-transparency test passes. The periodic
six-cell x86-64/AArch64/ARMv7 O0/O2 Hello checkpoint passed on the immediately
preceding exact release build and was not repeated for this verifier-only
increment. No broad Rust, Python, fixture, architecture, DecBench, or Joern
suite ran.
