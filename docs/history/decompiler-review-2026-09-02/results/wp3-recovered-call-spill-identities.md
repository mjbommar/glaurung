# WP3 recovered-call spill identities

Commit `316697e7` moves the recovered-callee-layout spill resolver onto the
pipeline-owned `ValueIdentities` sidecar.

A recovered callee contract can require an adjacent ABI setup value to be
traced through a promoted stack object before it reaches the call. Previously
that resolver accepted the intermediate object only when its rendered name had
a `local_*` or `stack_*` prefix. A later high-variable rename could therefore
leave the same proven storage identity explicit and degrade `callee(arg0)` into
setup statements followed by an unresolved call argument.

The production path now asks `is_promoted_stack_object`; the identity-free
compatibility entry point retains the historical spelling fallback. The
regression gives the promoted object an opaque `frame_object` spelling and
connects an opaque argument temporary to exact `rdi#1` identity, proving that
the call receives `arg0` because of producer-owned identity rather than either
display name.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::call_args::tests::recovered_layout_follows_opaque_promoted_spill_identity -- --exact --test-threads=1
1 passed; 4644 filtered out

cargo test --features python-ext --lib ir::call_args::tests:: -- --test-threads=4
127 passed; 4518 filtered out; test execution 0.21s

uv run maturin develop
success

uv run pytest python/tests/test_decompiler_fixture_harness.py::test_real_transitive_callee_contract_recovers_untouched_leading_argument -q
1 passed
```

The compiled fixture initially exposed a test-only formatting assumption:
valid `void *arg0` output was rejected because the assertion required
`* arg0`. Commit `e4d20055` makes that assertion require the pointer declarator
semantically (`\\*\\s*arg0`) and the fixture passes without changing output or
weakening its three-argument and exact-call checks.

This closes one recovered-call consumer in the current WP3 identity audit. It
does not complete pre-AST SSA migration, universal identity attribution and
invalidation, or the remaining wildcard-consumer audit. The compiled fixture
directly covers recovered call layout and untouched ABI arguments, so the
four-cell Hello matrix was not repeated for this internal role migration.
