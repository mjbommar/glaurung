# WP3 call-contract expression origins

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `65de3b46` makes call-site contract recovery inspect semantic expression
values. A direct named target behind an `OriginSet` retains its catalog
prototype, while attributed argument expressions retain the same recovered C
types as their unwrapped forms.

This closes the upstream contract boundary behind the preceding named-format
renderer repair. The renderer no longer has to be the only component that
recognizes an attributed callee: contract refresh and other direct callers of
`recover_call_site_spec` receive the same catalog and argument facts.

The type lattice is unchanged. Unknown values still become `long`, unsupported
callee names still have no catalog declaration, and each recovered call-owned
prototype remains exact-arity even when its callee declaration is variadic.

## Focused TDD

The exact contract uses an attributed named `printf` target, an attributed
literal format, and an attributed stack-address tail. Before the repair, the
catalog lookup failed at the target wrapper and `callee_prototype` was absent.
Without semantic argument classification, both attributed arguments would also
fall back to `long`.

After the repair:

```text
cargo test --features python-ext --lib \
  ir::call_contracts::tests::attributed_call_values_retain_catalog_and_argument_types \
  -- --exact
1 passed; 0 failed; 4,676 filtered out

cargo test --features python-ext --lib ir::call_contracts::tests -- --nocapture
25 passed; 0 failed; 4,652 filtered out; 0.21 s test execution
```

The module slice covers catalog decoration, fixed and variadic arity, pointer
and float storage classes, void-result removal, typed refresh, conflicting
prototype fallback, and unknown-call conservatism.

## Release evidence and scope

`uv run maturin develop --release` completed successfully. No additional broad
suite or fixture matrix was run: the preceding named-format record already
documents the only selected real-format test and its unrelated shared-snapshot
whitespace expectation failure.

This is one bounded WP3 pre-render semantic consumer. It does not add library
contracts, infer unsupported types, or complete universal expression
attribution.
