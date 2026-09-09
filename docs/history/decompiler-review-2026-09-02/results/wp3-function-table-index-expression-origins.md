# WP3 function-table index expression origins

Commit `3889f7e5` closes the scaled-index reconstruction boundary in
`function_tables`.

A relocation-proven table lookup can build its byte offset in a separate
instruction and then use that temporary in the table address. Recovery already
recognized the scaled expression through its reaching definition, but replacing
the multiply/shift form with the semantic element index discarded the consumed
arithmetic expression's owners. Structured line mappings therefore omitted the
instruction that produced the recovered `ops[index]` subexpression.

The scaled-index resolver now carries the deterministic expression-origin union
through bounded register-definition, cast, multiply, shift, and zero-addition
normalization. It attaches that union to the surviving semantic index. Exact
pointer scale, relocation, table completeness, and recursion-depth proofs are
unchanged.

## Focused evidence

The existing attributed scaled-index test was strengthened and observed red:
the table entry recovered but its semantic index had no owner. After repair:

```text
cargo test --features python-ext --lib \
  ir::function_tables::tests::expression_origins_do_not_hide_a_scaled_table_index \
  -- --exact --quiet
1 passed; 4,735 filtered out

cargo test --features python-ext --lib ir::function_tables::tests:: --quiet
14 passed; 4,722 filtered out
```

An exact detached release build of `3889f7e5` passed the build guard with native
SHA-256 `64fb109ae8f5fe19acb77b2e0163dee48c16cea5c00945a9a6501ab83cc1304f`.
The directly owning real dispatcher remained green:

```text
pytest -q \
  python/tests/test_decompiler_fixture_structural.py::test_dispatch_recovers_portable_local_function_table
1 passed
```

No broad Rust, Python, fixture, architecture, DecBench, or Joern suite ran. The
16-cell cross-architecture O0/O2 Hello checkpoint passed immediately before
this local function-table reconstruction increment and was not repeated.
