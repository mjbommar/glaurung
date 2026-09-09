# WP3 coalesced tail-value identity

Commit `4be3e995` migrates the value-equality proof used by proven vtable
tail-call recovery from exact-single-candidate SSA objects to stable `ValueId`
sets. Two rendered registers may each represent several non-interfering SSA
values after legal coalescing. They denote the same value family precisely when
both identity sets exist, are nonempty, and are equal.

Different sets and missing identity evidence still decline. The no-sidecar
compatibility path retains direct register equality, while production
identity-aware recovery no longer needs an exact singleton or display-name
comparison at this boundary.

## Focused evidence

The coalesced-value contract was observed red before implementation:

```text
cargo test --features python-ext --lib \
  coalesced_registers_match_only_the_same_nonempty_value_id_set
1 passed; 4,754 filtered out

cargo test --features python-ext --lib ir::call_args::tail_calls::tests::
16 passed; 4,739 filtered out
```

The contract proves equal two-value sets match, a differing two-value set does
not, and two missing identities do not become equal by absence.

An exact detached release build of `4be3e995` produced native SHA-256
`4ce27228e177bee7217e887d3d03536e3b7c560a142ebe14fcde37fe6fc7556c`.
The directly owning
`167_rust_trait_objects:rustc:O2:rust_dyn_apply` cell reports no regression and
retains its terminal vtable call and return. Its broader pre-existing Rust
signature/type debt remains outside this identity migration. The periodic
six-cell Hello checkpoint passed on the preceding output-changing increment and
was not repeated. No broad Rust, Python, fixture, architecture, DecBench, or
Joern suite ran.
