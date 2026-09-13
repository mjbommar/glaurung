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

## Internal authority closure

Follow-on commit `8b9da483` removes the remaining optional-identity engine from
DWARF aggregate-field recovery. Non-test builds can now construct only
`DwarfFieldAuthority::Exact(&ValueIdentities)`; the identity-free adapter and
its promoted-local spelling rule compile only for legacy unit tests. Pointer
inference, definition compatibility, and final field annotation therefore
cannot disagree by silently selecting a missing sidecar in shipped code.

Focused evidence:

```text
cargo test --features python-ext ir::dwarf_fields::tests:: --lib -- --test-threads=1
13 passed; 0 failed; 4833 filtered out

cargo check --features python-ext
exit 0; no new dwarf_fields warning

uv run maturin develop
exit 0

uv run python tools/build_guard.py
fresh
```

The required post-commit Python gate ran once with fail-fast. It passed the
former ARM Thumb and hard-float blockers and stopped at the independently known
committed-baseline disagreement at 17%:

```text
uv run pytest -q python/tests/ -x
FAILED test_decompiler_arch_roundtrip.py::test_the_committed_baseline_is_valid_and_has_a_clean_control_lane
```

That disagreement is the already-recorded x86-64 control verdict mismatch for
fixtures 157, 172, and 81. Neither baseline was regenerated from the shared
dirty checkout. No fixture sweep, DecBench, Joern, output, corpus, or timing
claim accompanies this authority-only follow-on. DWARF-field identity authority
is now internally closed; wider WP3 invalidation and origin work remains.
