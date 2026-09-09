# WP3 function-table address expression origins

Commit `5f26fa50` closes the complete address-proof ownership boundary in
`function_tables`.

Recovering `ops[index]` consumes more than the final pointer load. A separate
definition can produce the scaled index, another can establish the
relocation-proven table base, and an address expression combines them. Earlier
increments retained the semantic index and copied call target, but these
address contributors could still disappear or become nested origin carriers
when the dereference became a `FunctionTableEntry`.

The resolver now gathers deterministic expression ownership through the same
bounded reaching-definition graph used by the table proof. It composes the
scaled definition, table-base definition, address calculation, and load owner
onto one canonical recovered entry while leaving the index's own precise owner
attached to the index subtree. The 16-step recursion cap, complete relocation
requirements, exact scale checks, and transfer-clobber refusals are unchanged.

## Focused evidence

The scaled-table contract was strengthened and observed red: only the outer
load owner survived. After repair, the root owns all four contributors and the
index retains its specific scaled-definition owner.

```text
cargo test --features python-ext --lib \
  ir::function_tables::tests::expression_origins_do_not_hide_a_scaled_table_index \
  -- --exact --quiet
1 passed; 4,735 filtered out

cargo test --features python-ext --lib ir::function_tables::tests:: --quiet
14 passed; 4,722 filtered out
```

An exact detached release build of `5f26fa50` passed the build guard with native
SHA-256 `7fbee9cc44199b78ab366b163f7726e57b08aafb50012b74ecd3e17315af41ee`.
The directly owning real dispatcher remained green:

```text
pytest -q \
  python/tests/test_decompiler_fixture_structural.py::test_dispatch_recovers_portable_local_function_table
1 passed
```

No broad Rust, Python, fixture, architecture, DecBench, or Joern suite ran. The
16-cell cross-architecture O0/O2 Hello checkpoint passed two increments earlier
and was not repeated for this local provenance composition.
