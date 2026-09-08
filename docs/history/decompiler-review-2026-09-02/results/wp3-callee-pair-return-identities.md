# WP3 callee pair-return identities

Commit `489622b4` removes display-name classification from callee-side
two-register integer-result composition in `src/ir/callee_return_pair.rs`.

The production pipeline now supplies `ValueIdentities` when it:

- tracks the reaching high result half through nested control flow;
- invalidates that reaching value after a nested redefinition; and
- refuses a recovered integer-pair contract when the selected low expression
  is actually from a floating-point result bank.

Candidate sets must identify the requested storage exactly. Missing or mixed
identity evidence declines the rewrite. The original public function remains
an explicit no-sidecar compatibility wrapper for local callers and tests.

The exact regression accepts opaque values whose identities are `rax` and
`rdx`, rejects misleading `rdx#...` text backed by `rax`, and recognizes an
opaque `xmm0` low value as the SSE conflict that must prevent integer-pair
composition.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::callee_return_pair::tests::pair_result_banks_use_exact_identity_not_display_spelling \
  -- --exact
# 1 passed; 4,486 filtered out

cargo test --features python-ext --lib ir::callee_return_pair::tests::
# 10 passed; 4,477 filtered out

uv run maturin develop
uv run python tools/build_guard.py
# fresh

uv run python tools/dectest.py \
  195_by_value_aggregates:gcc:O0:bv195_make_quad --show
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used
for this bounded increment.
