# WP3 copy read-count identities

Commit `face2852` makes the shared copy-propagation read walker distinguish a
promoted-stack store destination from a pointer read using pipeline-owned
`ValueIdentities`.

The AST overloads `Store { addr: Reg(...), ... }`: a promoted scalar store uses
the bare register as a destination, while an ordinary indirect store reads its
address. Previously the central walker resolved that distinction only from
`local_*` spelling. An opaque promoted object therefore gained a fake read,
which could corrupt exact single-use counts, retain dead copies, or block
adjacent value folding.

The walker now has one internal optional-identity implementation. Existing
identity-free helpers preserve compatibility behavior; production counted
propagation, dead-copy cleanup, adjacent guard/effectful/promoted-value proofs,
and `for`-header scratch liveness supply the sidecar they already own. Exact
promoted ownership classifies the target as a write; absent or ambiguous
production identity does not infer storage from spelling.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::copy_prop::reads::tests::authoritative_identity_counts_opaque_store_target_as_write -- --exact
1 passed; 4642 filtered out

cargo test --features python-ext --lib ir::copy_prop::reads::tests::spelling_fallback_counts_legacy_local_store_target_as_write -- --exact
1 passed; 4642 filtered out

cargo test --features python-ext --lib ir::copy_prop:: -- --test-threads=4
74 passed; 4569 filtered out; test execution 0.01s

uv run maturin develop
success

uv run pytest python/tests/test_decompiler_arm_frame_spills.py -q
1 passed
```

This closes the read-accounting prerequisite for the current WP3 copy consumer
migrations. It does not complete pre-AST SSA migration, all identity-aware
semantic consumers, universal invalidation, or expression-origin coverage. The
compiled frame-spill fixture directly covers the affected storage path, so the
four-cell Hello matrix was not repeated for this internal role change.
