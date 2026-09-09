# WP3 created-select return origins

Commit `7beb26f9` closes the adjacent expression-carrier boundary in
`select_fold::fold_created_select_return`.

A select created by lifting or an earlier diamond fold can be assigned to a
register or promoted stack local immediately before that value is returned.
The cleanup previously matched the select, promoted address, and returned
register by their outer enum variant. Expression provenance therefore kept the
otherwise redundant assignment/store and result temporary alive.

The repair compares the semantic select, destination, and returned value while
moving the complete owned select into the return. The removed result-read owner
transfers to the surviving statement. For promoted storage, the consumed
address owner transfers as well. Exact promoted-local naming, same-destination,
adjacency, and comment/no-op-only gap requirements remain unchanged.

## Focused evidence

The attributed register contract was observed red before repair: its two
statements remained instead of folding to one return. The promoted-local sibling
covers the address path added by the same repair.

```text
cargo test --features python-ext --lib \
  ir::select_fold::tests::attributed_created_select_return_unions_both_statements \
  -- --exact
1 passed; 4,732 filtered out

cargo test --features python-ext --lib \
  ir::select_fold::tests::attributed_promoted_select_return_preserves_consumed_address_owner \
  -- --exact
1 passed; 4,733 filtered out

cargo test --features python-ext --lib ir::select_fold::tests::
24 passed; 4,710 filtered out
```

An exact detached release build of `7beb26f9` passed the build guard with native
SHA-256 `60f73a0b72f13bcb34c1038c742a63012029e21f964ef29da98a3cd9ab90ca99`.
The directly owning real controls pass:

```text
pytest -q \
  python/tests/test_decompiler_fixture_structural.py::test_signs_renders_lifted_select_as_pure_ternary
2 passed (GCC O0 and O2)
```

The real output retains both pure value alternatives as two ternaries without
inventing statement-level control flow. No broad Rust, Python, fixture,
DecBench, or Joern suite ran. The periodic cross-architecture Hello checkpoint
passed on the immediately preceding general expression increment and was not
repeated for this local temporary cleanup.
