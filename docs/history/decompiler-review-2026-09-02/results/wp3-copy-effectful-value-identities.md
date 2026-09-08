# WP3 adjacent effectful-value identities

Commit `3e8cb088` gives the late adjacent effectful-value mover an
identity-aware production entry point. This pass moves a one-use call
expression into its immediately adjacent consumer, deleting the temporary so
the call is evaluated exactly once.

Previously it classified both the temporary destination and a promoted-store
consumer from register spelling. That created two symmetric errors for opaque
names: promoted stack storage could be treated as a disposable scratch, while
a genuine promoted store target could be rejected because it did not begin
with `local_`. The production prepare pipeline now supplies `ValueIdentities`.
Exact promoted-stack ownership excludes a value from scratch movement and
admits the store-target form; missing or ambiguous identity fails closed. The
old wrapper keeps spelling behavior for identity-free compatibility callers.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::copy_prop::adjacent::tests::identity_aware_effectful_move_rejects_opaque_stack_destination -- --exact
1 passed; 4638 filtered out

cargo test --features python-ext --lib ir::copy_prop::adjacent::tests::identity_aware_effectful_move_accepts_opaque_stack_store -- --exact
1 passed; 4638 filtered out

cargo test --features python-ext --lib ir::copy_prop:: -- --test-threads=4
70 passed; 4569 filtered out; test execution 0.00s

uv run maturin develop
success

uv run pytest python/tests/test_decompiler_lazy_call_select.py -q
1 passed
```

This advances the WP3 copy-propagation consumer migration. It does not complete
the planned pre-AST SSA implementation, universal invalidation, or origin
coverage. The four-cell Hello matrix was not rerun because this is a storage-
role migration and the exact compiled lazy-call fixture exercises the changed
output path more directly.
