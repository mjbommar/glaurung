# WP3 function-table target expression origins

Commit `48bf0ce5` closes the copied-call-target expression boundary in
`function_tables`.

Relocation-proven table loads can be assigned to a register before that
register becomes an indirect call target. The existing promotion recovered the
semantic `FunctionTableEntry`, but stripped the defining expression's owner and
the target register's use-site owner while replacing the expression. Structured
line mappings therefore omitted instructions that contributed to the recovered
call target.

The copy resolver now carries a deterministic origin union through bounded
register and cast chains. The recovered table entry receives both the defining
entry and use-site owners. The existing depth bound, exact reaching-definition
map, complete relocation proof, and transfer-clobber refusals are unchanged.

## Focused evidence

The new ownership contract was observed red first: the semantic table call was
recovered, but its target had no owners. After the repair:

```text
cargo test --features python-ext --lib \
  ir::function_tables::tests::copied_table_call_target_composes_definition_and_use_origins \
  -- --exact --quiet
1 passed; 4,735 filtered out

cargo test --features python-ext --lib ir::function_tables::tests:: --quiet
14 passed; 4,722 filtered out
```

An exact detached release build of `48bf0ce5` passed the build guard with native
SHA-256 `ffbd9d3640289984cc7feea3716b6f87b15f3f97233a398091826dd6dc449154`.
The directly owning real table integration remained green:

```text
pytest -q \
  python/tests/test_decompiler_fixture_structural.py::test_dispatch_recovers_portable_local_function_table
1 passed
```

No broad Rust, Python, fixture, architecture, DecBench, or Joern suite ran. The
periodic 12-cell cross-architecture Hello checkpoint remained recent and was
not repeated for this provenance-only expression replacement.
