# WP3 DWARF field storage identities

Commit `696af8e1` moves all promoted-store classification inside DWARF field
recovery to pipeline-owned `ValueIdentities`.

The pass has three mutually dependent phases: infer pointer types, reject a
candidate when any definition is incompatible, and annotate exact aggregate
field accesses. Each phase previously interpreted a bare-register `Stmt::Store`
as a promoted scalar assignment only when its destination had `local_*` or
`stack_*` spelling. Allowing the phases to disagree would be worse than a
single missed annotation: one could infer a struct-pointer fact that another
then applied as an offset-zero pointer store.

`annotate_function_fields` remains the identity-free compatibility API. The new
`annotate_function_fields_with_identities` carries one optional sidecar through
every recursive structured body in all three phases, and the production
renderer supplies the sidecar it already owns. Exact promoted ownership admits
the scalar definition and suppresses false address annotation; missing
ownership refuses both, regardless of presentation spelling.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::dwarf_fields::tests::opaque_promoted_stack_result_uses_identity_for_pointer_type -- --exact --test-threads=1
1 passed; 4651 filtered out

cargo test --features python-ext --lib ir::dwarf_fields::tests::unowned_local_spelling_does_not_gain_dwarf_pointer_type -- --exact --test-threads=1
1 passed; 4651 filtered out

cargo test --features python-ext --lib ir::dwarf_fields::tests:: -- --test-threads=4
13 passed; 4639 filtered out

uv run maturin develop
success

uv run pytest python/tests/test_decompiler_control_flow_semantics.py::test_clang_o0_linked_list_sum_round_trips_exact_instruction_bytes -q
1 passed
```

The compiled linked-list check requires recovered `->val` and `->next` fields,
recompiles both decompiled functions, and compares runtime behavior. At the
time of that check, `tools/build_guard.py` marked only the concurrent untracked
`src/disasm/native_aarch64.rs` newer than the extension. The extension itself
was rebuilt after both files in this commit changed, so this is valid evidence
for the DWARF-field transaction but not a globally fresh dirty-checkout claim.

The isolated committed-tree census records 5,184 declared Rust tests, 2,479 in
IR, and zero outside every gate. This closes DWARF aggregate-field recovery's
storage-name readers; it does not complete WP3's remaining wildcard audit,
expression ownership, or universal identity lifecycle.
