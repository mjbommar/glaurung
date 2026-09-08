# WP3 semantic display-name fallbacks

Commits `633df9f7` and `db6c4756` remove two production cases where installing
the authoritative value-identity sidecar still permitted semantic decisions
from a `varN` display spelling.

Loop-entry coalescing now requires `ValueIdentities::exact` whenever a sidecar
is present. Pointer and high-bit signedness refinement uses the same rule for
high values; promoted stack objects remain eligible through their distinct
storage model. A missing or ambiguous identity fails closed. Compatibility
callers that provide no sidecar retain the legacy spelling behavior until they
are migrated.

Focused validation used only exact Rust tests:

```text
installed_identity_authority_does_not_fall_back_to_var_spelling
1 passed; 4,421 filtered out

opaque_exact_identities_authorize_loop_entry_coalescing
1 passed; 4,421 filtered out

ambiguous_opaque_identity_keeps_loop_entry_copy
1 passed; 4,421 filtered out

installed_identity_authority_does_not_trust_var_spelling_for_type_refinement
1 passed; 4,422 filtered out

exact_opaque_identity_is_eligible_for_pointer_refinement
1 passed; 4,422 filtered out

ambiguous_opaque_identity_is_not_eligible_for_pointer_refinement
1 passed; 4,422 filtered out

origin_wrapped_high_bit_constant_used_by_unsigned_widening_is_unsigned
1 passed; 4,422 filtered out
```

Each command was `cargo test --features python-ext --lib
ir::<module>::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. Other semantic display-name consumers remain
open under WP3.
