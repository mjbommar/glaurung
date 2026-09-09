# WP3 pointer-refinement identity consumer

Commit `697d6358` migrates pointer-value eligibility in `high_variables` from
the presentation-only `varN` convention to the projected opaque SSA identity
sidecar.

The existing entry point remains for isolated callers. The production
DecBench renderer now supplies the role-projected identities. Existing
`varN` and promoted-local behavior is unchanged; an otherwise opaque role is
eligible only when it has one exact SSA identity. Multiple candidates fail
closed and do not acquire a pointer type.

The positive test uses a proven C-string source. A preliminary numeric-address
test correctly stayed untyped because this pass deliberately does not treat an
unresolved integer VA as pointer evidence; the production rule was not weakened
to make that test pass.

Focused validation:

```text
cargo test --features python-ext --lib ir::high_variables::tests::exact_opaque_identity_is_eligible_for_pointer_refinement -- --exact
1 passed; 4,396 filtered out

cargo test --features python-ext --lib ir::high_variables::tests::ambiguous_opaque_identity_is_not_eligible_for_pointer_refinement -- --exact
1 passed; 4,396 filtered out

cargo test --features python-ext --lib ir::high_variables::tests::
29 passed; 4,368 filtered out
```

This is an incremental WP3 consumer migration. It does not complete identity
invalidation, migrate signedness rules, or implement WP6's general type solver.

## Coalesced-storage follow-up

Commit `11afa94a` replaces pointer-local eligibility's one-exact-value check
with one unambiguous physical storage base. A value representing multiple
non-interfering versions of `rax` can now recover `char *` from a proven string
origin; candidates spanning different carriers still receive no pointer type.
The positive same-storage behavior contract was observed red first.

All 37 focused `ir::high_variables::tests::` tests pass after the change, with
4,727 unrelated tests filtered out. This includes the original exact-value and
mixed-storage refusal contracts. No release build, fixture, broad suite,
DecBench, Joern, GED, performance, or corpus-wide measurement ran.
