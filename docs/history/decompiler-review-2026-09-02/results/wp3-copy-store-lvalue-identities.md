# WP3 copy-store lvalue identities

Commit `e4bd8cb4` makes copy propagation preserve an indirect store's lvalue
category using the pipeline-owned promoted-stack identity sidecar. Previously,
`subst_store_addr` accepted authoritative identities indirectly through its
caller but still recognized protected stack objects only from `local_*` text.
An opaque promoted object copied through a scratch could therefore be
substituted as an ordinary scalar and change an indirect store into an
assignment.

The two production linear walkers now thread `ValueIdentities` into that exact
substitution boundary. An exact promoted-stack identity protects the lvalue;
missing or ambiguous production identity does not manufacture storage from a
name. The identity-free compatibility paths retain their legacy spelling rule.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::copy_prop::subst::tests::authoritative_identity_protects_opaque_stack_lvalue -- --exact
1 passed; 4636 filtered out

cargo test --features python-ext --lib ir::copy_prop::subst::tests::spelling_fallback_protects_legacy_promoted_lvalue -- --exact
1 passed; 4636 filtered out

cargo test --features python-ext --lib ir::copy_prop:: -- --test-threads=4
68 passed; 4569 filtered out; test execution 0.01s

uv run maturin develop
success

uv run pytest python/tests/test_decompiler_arm_frame_spills.py -q
1 passed
```

This is a bounded WP3 consumer migration, not completion of authoritative SSA,
identity invalidation, or universal expression-origin coverage. The periodic
four-cell Hello canary was not repeated because this increment changes storage
classification only; its latest x86-64/AArch64 O0/O2 run remains green.
