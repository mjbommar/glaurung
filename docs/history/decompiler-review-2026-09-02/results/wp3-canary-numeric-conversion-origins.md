# WP3 canary numeric-conversion transparency

Date: 2026-09-10

## Defect and repair

The stack-canary semantic walkers in `src/ir/canary.rs` recursed through an
integer `Cast` but stopped at its scalar-conversion sibling,
`Expr::NumericConvert`. A converted stack object, TLS displacement, or named
guard could therefore be hidden from the otherwise unchanged canary proof.

Commit `aeb0c581` makes `expr_mentions_slot`,
`expr_mentions_canary_marker`, and `expr_mentions_guard` treat numeric
conversion as a transparent expression wrapper. It does not broaden the
accepted canary symbols, TLS offsets, architectures, or control-flow shapes.

## Red/green evidence

The focused test was first observed red at its first assertion: a converted
`stack_0` was not found. After the repair, the complete owning module passes:

```text
cargo test --features python-ext ir::canary::tests:: --lib
25 passed; 0 failed; 4750 filtered out
```

## Exact-commit product evidence

A clean detached worktree at
`aeb0c5815afce34d581025554d2c88df5d9dd3a6` was release-built with CPython
3.12.13. `tools/build_guard.py` reported the extension fresh:

```text
python/glaurung/_native.cpython-312-x86_64-linux-gnu.so
SHA-256 28880972224be32e82464dc99bacc88990958bc7de146903e1fd2080e1439791
```

Only directly owning product checks ran:

```text
uv run --no-sync python tools/dectest.py \
  20_graph_bfs:gcc:O2:graph_bfs --arch aarch64 --show
SCOPED: 1 lane of 3304 (0%) - no regressions in scope

uv run --no-sync pytest -q \
  python/tests/test_decompiler_arch_roundtrip.py::test_aarch64_o2_stack_protected_functions_return_through_their_canary
2 passed
```

No broad suite, corpus sweep, DecBench run, or baseline refresh was performed.
This closes one expression-consumer variant; WP3's universal origin-survival
criterion remains open.
