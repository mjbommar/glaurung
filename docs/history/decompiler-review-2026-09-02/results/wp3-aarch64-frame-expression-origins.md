# WP3 AArch64 frame expression origins

Date: 2026-09-08

Commit: `a66033bc`

## Defect and repair

AArch64 prologue and epilogue recognition was already transparent to statement
origins, but several shape checks still matched child expressions directly.
Origins on a promoted save address/value, stack-adjustment expression or
operand, frame-pointer source, promoted-record address, or paired restore made
valid machine-frame bookkeeping survive into decompiled C.

`src/ir/arm64_prologue.rs` now classifies each of those values through
`Expr::semantic()`. The existing safety boundaries are unchanged: the pass
still requires exact `fp`/`lr` and `sp` roles, positive matching stack widths,
promoted-object authority, exact frame-record offsets, and a complete paired
restore before removing statements. Existing statement-origin unions remain
the provenance of synthesized comments.

## Focused validation

The existing canonical prologue, epilogue, and promoted-frame-record contracts
were strengthened so their relevant child expressions carry independent
origins. The canonical prologue contract was observed red before the repair,
with all five input statements surviving. After the repair, the complete owning
module passes:

```text
running 16 tests
................
test result: ok. 16 passed; 0 failed; 0 ignored; 4680 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit and a cache-backed build directory:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run pytest \
  'python/tests/test_linux_arm_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-aarch64]' \
  -q
```

Results:

```text
native extension: fresh
1 passed
```

This is one exact release-built AArch64 Hello World cell, not the complete ARM
matrix or repository suite. It closes the known AArch64 frame recognizers'
raw-expression readers; universal WP3 attribution and explicit invalidation
remain open.
