# WP3 unsigned-literal identity consumer

Commit `2ccd8ce1` migrates use-proven high-bit integer-literal refinement from a
`varN` presentation-name gate to the pipeline-owned opaque SSA identity sidecar.

An exact opaque value initialized from a high-bit literal can now become
unsigned when every definition and use proves the positive interpretation. An
ambiguous opaque value remains signed. Existing `varN`, origin-wrapped,
wide-signed-comparison, and signed-use behavior remains unchanged.

The exact-identity test was observed red before the identity-aware eligibility
rule existed. Focused validation after implementation:

```text
exact_opaque_high_bit_constant_used_unsigned_is_retyped
1 passed; 4,414 filtered out

ambiguous_opaque_high_bit_constant_stays_signed
1 passed; 4,414 filtered out

origin_wrapped_high_bit_constant_used_by_unsigned_widening_is_unsigned
1 passed; 4,414 filtered out

high_bit_constant_with_a_signed_use_stays_signed
1 passed; 4,414 filtered out

high_bit_bound_compared_in_a_wide_signed_domain_is_unsigned
1 passed; 4,414 filtered out
```

Each case used `cargo test --features python-ext --lib
ir::high_variables::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. This closes one more name-based semantic
consumer; the complete WP3 consumer audit remains open.

## Follow-up: authoritative signed comparison domain

Commit `f889e200` removes the adjacent duplicated `varN` spelling rule from
wide-signed-bound recognition. The proof now asks the shared declaration
contract whether the comparison operand is rendered as signed eight-byte
integer. An exact opaque high-bit value compared with an otherwise untyped
opaque machine-word bound is therefore refined correctly, while signed uses and
ambiguous candidate identities retain their existing refusals.

The new exact opaque-bound test was observed red before the declaration query
replaced the spelling check. It and three adjacent tests pass individually with
4,415 unrelated tests filtered out. No broad suite or external benchmark ran.

## Coalesced-storage follow-up

Commit `11afa94a` also migrates the high-bit literal eligibility gate from one
exact SSA value to one unambiguous physical storage base. When every definition
and use already proves the positive unsigned interpretation, multiple
non-interfering versions of the same carrier may now receive that signedness.
Candidates spanning different carriers remain signed.

The same-storage unsigned contract was observed red first. It and the pointer
follow-up are covered by all 37 focused `ir::high_variables::tests::` tests,
which pass with 4,727 unrelated tests filtered out. No release build, fixture,
broad suite, DecBench, Joern, GED, performance, or corpus-wide measurement ran.
