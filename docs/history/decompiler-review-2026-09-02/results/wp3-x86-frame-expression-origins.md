# WP3 x86 frame expression origins

Date: 2026-09-08

Commit: `1412bdca`

## Defect and repair

The x86 epilogue recognizer correctly retained statement origins, but several
shape checks still matched child expressions directly. An origin on the source
of `rsp = rbp`, a promoted restore, or either side of `rsp += N` made the same
machine teardown stop matching and leak into decompiled C. The same raw-reader
pattern remained in adjacent balanced-save/restore, omit-frame-pointer,
cdecl32-alignment, and canonical-prologue helpers.

`src/ir/x86_prologue.rs` now classifies the containing expression and its
operands through `Expr::semantic()`. This does not weaken the recognizers:
register identity, exact widths and offsets, promoted-slot identity, adjacency,
balanced save/restore, and liveness checks are unchanged. Origins remain on the
collapsed annotation through the existing union operation.

## Focused validation

The existing ownership contracts were strengthened with origins on the source
of `rsp = rbp`, both operands of stack teardown, and the promoted restore
source. `attributed_leave_epilogue_unions_exact_machine_owners` was observed red
before the repair: the attributed assignment survived beside the epilogue
comment. After the repair, the four exact strengthened contracts pass and the
complete owning module passes:

```text
running 45 tests
.............................................
test result: ok. 45 passed; 0 failed; 0 ignored; 4651 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit and cache-backed build directory:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run pytest \
  'python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-gcc]' \
  -q
```

Results:

```text
native extension: fresh
1 passed
```

This is one exact release-built Hello World cell, not the full Hello collection
or repository suite. It closes the x86 frame recognizers' known raw-expression
readers; the broader WP3 requirement for universal production attribution and
explicit invalidation remains open.
