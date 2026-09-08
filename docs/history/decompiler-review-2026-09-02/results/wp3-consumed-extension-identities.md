# WP3 consumed-extension identity consumer

Commit `403296e0` migrates typed consumed-extension cleanup from
presentation-name heuristics to the pipeline-owned opaque SSA identity sidecar.

When modular arithmetic is assigned to a narrow destination, an exact opaque
destination identity can now prove that a surrounding machine-parent extension
is unobservable. An ambiguous opaque destination fails closed and retains the
extension. Compatibility callers without a sidecar retain their prior behavior,
as do promoted stack locals.

The two identity tests were observed red before the identity-aware entry point
existed. Focused validation after implementation:

```text
exact_opaque_destination_consumes_machine_only_extension
1 passed; 4,412 filtered out

ambiguous_opaque_destination_keeps_machine_extension
1 passed; 4,412 filtered out

narrow_destination_consumes_machine_only_operand_extension
1 passed; 4,412 filtered out
```

Each case used `cargo test --features python-ext --lib
ir::typed_simplify::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. This closes the immediate cluster of
render-time consumers identified after declaration-plan migration, but does not
complete WP3's full semantic-consumer audit.
