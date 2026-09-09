# WP3 indirect-result expression origins

Date: 2026-09-08

Commit: `f93e8655`

## Defect and repair

The indirect aggregate-result pass had already been made transparent to
statement origins, but its expression readers remained raw. An origin around
an AAPCS64 `sp + offset` coordinate, a copy reaching `x8`, a SysV `rsp`
adjustment or hidden first argument, or a promoted `StackAddr` prevented an
otherwise proven result buffer from being hinted or bound to its call.

`src/ir/aapcs64_indirect_result.rs` now reads those frame coordinates,
arithmetic operands, and promoted objects through `Expr::semantic()`. The
existing fail-closed boundaries remain: only ABI-defined frame bases and
conventions qualify, all identity candidates must agree, calls clobber tracked
state, and only an indirect-return size contract permits a hint or destination.

## Focused validation

The existing AAPCS64 copy-chain, SysV hidden-result, and promoted-buffer tests
now carry origins on their relevant expressions. The AAPCS64 test was observed
red before the repair because the attributed `sp + 16 -> x0 -> x8` chain
produced zero hints. After the repair, the complete owning module passes:

```text
running 6 tests
......
test result: ok. 6 passed; 0 failed; 0 ignored; 4690 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit and a cache-backed build directory:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run python tools/dectest.py \
  198_aggregate_return_edges:aarch64:O2:agr198_five_roundtrip --show
```

Result:

```text
native extension: fresh
SCOPED: 1 lane of 3304 (0%) - no regressions in scope
```

This is one exact AArch64 O2 aggregate-return round trip, not an architecture or
repository-wide gate. It closes the known expression-reader gap in indirect
aggregate-result recovery; universal WP3 attribution and explicit invalidation
remain open.
