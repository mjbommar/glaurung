# WP3 AST role identity projection

Commit `ef444751` moves one production AST cleanup off presentation-name
guessing and onto the opaque SSA identity sidecar.

Naming returns an exact raw-name to role-name map. The pipeline now projects
the existing `ValueIdentities` sidecar through that map without deleting its
storage-keyed entries, because later type recovery still consumes those
original keys. When multiple raw values receive one role name, their candidate
sets are unioned and the role remains explicitly ambiguous.

The late loop-entry copy coalescer consumes the projected sidecar. An exact
identity authorizes opaque, non-`varN` values; an ambiguous identity declines
the rewrite. A missing identity retains the legacy `varN` fallback so this is
an incremental migration rather than a big-bang conversion of every AST pass.

Focused validation used only the changed contract and its directly related
module:

```text
cargo test --features python-ext --lib ir::value_number::tests::role_projection_preserves_original_keys_and_explicit_ambiguity -- --exact
1 passed; 4,393 filtered out

cargo test --features python-ext --lib ir::latch_predicate::tests::ambiguous_opaque_identity_keeps_loop_entry_copy -- --exact
1 passed; 4,394 filtered out

cargo test --features python-ext --lib ir::latch_predicate::tests::
15 passed; 4,380 filtered out
```

This is WP3 progress, not WP3 completion. The remaining work is to migrate
additional AST consumers, replace the fallback when coverage is sufficient,
and complete conservative identity invalidation across all mutating passes.
