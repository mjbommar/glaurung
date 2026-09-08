# WP3 typed parameter-role metadata

Commit `7eeb84ca` extends `ValueIdentities` with source-parameter slot metadata.
The common pipeline attaches its authoritative `parameter_slots` while
projecting exact AST role aliases. A slot is recorded directly as a semantic
fact; an arbitrary alias merely spelled `argN` cannot create one. Renames move
slot candidates with value candidates, and collisions remain explicitly
ambiguous.

Commit `53eb97ec` migrates the first consumer. Callee-contract pointer
back-propagation now recognizes a source parameter through
`ValueIdentities::parameter_slot` whenever the authoritative sidecar is
installed. A fake `arg99` therefore cannot acquire pointer type from its
spelling, while an owned `arg0` and the compatibility no-sidecar copy-chain
path retain their established behavior.

Commit `14f6d24a` completes the authority migration across this pointer-copy
decision chain. Structured call discovery, recursive definition compatibility,
expression classification, and parameter-origin tracing all receive the same
identity context. With a sidecar installed, only exact values, typed parameters,
and separately modelled promoted storage are trusted. An unowned `var2` copy no
longer transports a pointer fact merely because of its spelling; an exact
`var2` still transports the owned `arg0` fact.

Commit `11ae7601` migrates exact type-role projection. The remapper already
receives pipeline-owned `param_slots`; it now derives the protected role set
from those slots rather than parsing every alias that looks like `argN`.
Consequently the real `arg0` remains protected from later storage definitions,
while an unrelated exact role called `arg99` is projected normally.

Focused validation used exact Rust tests only:

```text
role_projection_records_parameter_slots_without_parsing_alias_spelling
1 passed; 4,424 filtered out

role_projection_preserves_original_keys_and_explicit_ambiguity
1 passed; 4,424 filtered out

callee_pointer_contract_does_not_trust_an_unowned_arg_spelling
1 passed; 4,425 filtered out

attributed_authoritative_callee_refines_a_forwarded_argument
1 passed; 4,425 filtered out

recovered_callee_pointer_flows_back_through_one_exact_parameter_copy
1 passed; 4,425 filtered out

callee_pointer_contract_does_not_follow_an_unowned_var_copy
1 passed; 4,426 filtered out

recovered_callee_pointer_flows_back_through_one_exact_parameter_copy
1 passed; 4,426 filtered out

attributed_authoritative_callee_refines_a_forwarded_argument
1 passed; 4,426 filtered out

exact_role_projection_uses_parameter_slots_instead_of_arg_spelling
1 passed; 4,427 filtered out

float_role_projection_uses_opaque_identity_instead_of_numbered_spelling
1 passed; 4,427 filtered out
```

Each command was `cargo test --features python-ext --lib
ir::<module>::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. Remaining parameter-role consumers are still
open under WP3.
