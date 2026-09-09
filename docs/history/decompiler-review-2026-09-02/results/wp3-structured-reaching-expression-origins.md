# WP3 structured-reaching expression origins

Commit `8b27c665` makes promoted-home reaching analysis classify store addresses
and initializer sources through their semantic expression views. Both the
structured fixed-point path and the conservative label/goto path now preserve
the distinction between an attributed parameter-home initializer and an
attributed later mutation.

## Observed defect

The first positive-only test was insufficient: hiding both sides of
`home = arg0` happened to produce the same harmless verdict. Adding the
required negative control exposed the defect on a clean committed-tree build:
an attributed `home = 7` followed by a read of `arg0` incorrectly reported that
the read could not observe the mutation.

The repair uses `Expr::semantic()` only for the exact register classifications.
It does not strip the stored origin sets or relax the recursive expression-read
walk. The test requires all four cases:

- structured initializer remains harmless;
- goto-containing initializer remains harmless;
- structured mutation remains visible; and
- goto-containing mutation remains visible.

## Focused evidence

All commands used `TMPDIR=/home/mjbommar/.cache/glaurung/tmp`. While the shared
checkout temporarily referenced a missing in-flight AArch64 decoder corpus,
the RED and first GREEN runs used a detached clean worktree at committed
`master` plus only this patch.

```text
cargo test --features python-ext --lib \
  ir::structured_reaching::tests::expression_origins_preserve_home_initializers_and_mutations \
  -- --exact --nocapture
RED: structured attributed mutation assertion failed
GREEN: 1 passed; 0 failed

cargo test --features python-ext --lib ir::structured_reaching::tests -- --nocapture
8 passed; 0 failed; 4,672 filtered out

cargo test --features python-ext --lib ir::ast::param_spills::tests -- --nocapture
4 passed; 0 failed; 4,676 filtered out

uv run maturin develop --release
finished release profile; editable wheel installed

uv run python tools/dectest.py 11_call_shapes:gcc:O0:spill_combine --show
SCOPED: 1 lane of 838; no regressions in scope
```

No broad fixture or test sweep was run. The release build includes unrelated
concurrent shared-checkout edits; the clean-tree Rust run isolates this
increment's behavioral proof.
