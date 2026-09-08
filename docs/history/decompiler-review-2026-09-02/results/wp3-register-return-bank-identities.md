# WP3 register return-bank identities

Commit `4345efff` removes display-name classification from the register-resident
multi-bank return materializer in `src/ir/callee_return_bank.rs`.

The production pipeline supplies `ValueIdentities` for both supported shapes:

- mixed System V INTEGER/SSE aggregate returns; and
- System V `xmm0:xmm1` SSE-pair returns.

Assignment and call destinations, explicitly projected return values, nested
control paths, and pop invalidation now classify each carrier through complete
identity candidates. Missing or cross-bank evidence fails closed. The original
public functions remain explicit no-sidecar compatibility wrappers.

The exact regression accepts opaque values backed by `rax`, `xmm0`, and
`xmm1`, and rejects misleading `xmm1#...` text backed by `rax`.

Focused validation only:

```text
cargo test --features python-ext --lib \
  ir::callee_return_bank::tests::register_return_banks_use_exact_identity_not_display_spelling \
  -- --exact
# 1 passed; 4,487 filtered out

cargo test --features python-ext --lib ir::callee_return_bank::tests::
# 21 passed; 4,467 filtered out

uv run maturin develop
uv run python tools/build_guard.py
# fresh

uv run python tools/dectest.py \
  195_by_value_aggregates:gcc:O2:bv195_make_mixed --show
# SCOPED: 1 lane of 838; no regressions in scope
```

No broad Rust/Python suite, fixture matrix, DecBench run, or Joern run was used
for this bounded increment.
