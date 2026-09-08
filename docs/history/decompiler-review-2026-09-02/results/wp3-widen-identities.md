# WP3 contextual-widening identity consumer

Commit `17dff536` migrates contextual widening from presentation-name
heuristics to the pipeline-owned opaque SSA identity sidecar.

The production renderer supplies exact identities when deciding both the width
of an assignment destination and whether a narrow source needs an explicit
machine-width extension. An exact opaque identity can therefore receive the
same width-safe treatment as an argument or promoted local without requiring a
`varN` spelling. Multiple candidates fail closed to the conservative
machine-word declaration. Compatibility entry points retain their previous
behavior when no sidecar is supplied.

The two source-side tests were observed red before the identity-aware entry
point existed. Focused validation after implementation:

```text
exact_opaque_identity_is_widened_in_a_wide_context
1 passed; 4,409 filtered out

ambiguous_opaque_identity_is_not_widened
1 passed; 4,409 filtered out

exact_opaque_destination_keeps_its_arithmetic_narrow
1 passed; 4,410 filtered out

narrow_operands_of_a_wide_multiply_are_widened
1 passed; 4,409 filtered out

widening_a_signed_value_goes_through_its_unsigned_type
1 passed; 4,409 filtered out

a_register_local_is_never_narrowed_by_a_recovered_width
1 passed; 4,409 filtered out

attributed_assignment_is_widened_without_losing_its_owner
1 passed; 4,409 filtered out
```

Each case used `cargo test --features python-ext --lib
ir::widen::tests::<name> -- --exact`. No broad Rust, Python, fixture, DecBench,
or Joern suite was run. This closes the contextual-widening consumer, not WP3;
typed consumed-extension cleanup remains name-based.
