# WP3 recovered-layout storage identities

Date: 2026-09-08

Source commit: `5042ef6d`

## Result

Both convention-generic recovered-callee-layout folds now match adjacent call
setup destinations to the layout's authoritative ABI storage through
`ValueIdentities`. All candidates must identify the expected physical storage.
An opaque presentation value backed by `rdi` is accepted; a value spelled
`rdi#looks_versioned` but backed by `rax` is rejected.

Layout entries themselves remain authoritative cross-function facts and retain
their existing storage representation. The migration changes only how current
caller AST values are matched to those facts. No claim about AST-name
immutability is introduced, preserving the boundary established by the prior
`call_accumulate_bytes` rejection.

## Focused verification

```text
cargo test --features python-ext --lib \
  recovered_layout_setup_uses_exact_identity_not_display_spelling -- --nocapture
1 passed; 0 failed; 4482 filtered out

cargo test --features python-ext --lib 'ir::call_args::'
142 passed; 0 failed; 4341 filtered out; 0.22s

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py \
  11_call_shapes:clang:O0:call_into_spill --show
SCOPED: 1 lane of 838 - no regressions in scope
```

No broad Rust/Python suite, fixture sweep, DecBench, or Joern ran.
