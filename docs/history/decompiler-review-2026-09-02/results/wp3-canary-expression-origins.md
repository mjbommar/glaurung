# WP3 stack-canary expression origins

Date: 2026-09-09

Commit: `1e6f4743`

## Defect

The stack-canary pass already ignored statement-origin wrappers, but several
production classifiers still matched enclosed expressions literally. An
`Expr::Origin` on AArch64's GOT slot, saved address, promoted destination, exit
comparison, or failure-call target could therefore hide an otherwise proven
canary sequence. Replacement comments also omitted instruction owners attached
inside consumed expressions.

This is a provenance-consumer defect, not a relaxation of canary recognition.
The relocation name, TLS segment and displacement, exact dereference widths,
promoted stack-storage identity, comparison polarity, and exact
`__stack_chk_fail` target remain required.

## Change

`src/ir/canary.rs` now reads semantic expressions at every classification
boundary used by TLS/GOT recognition, split and ordinary canary saves, reload
and compare recovery, and structured exit checks. Its origin collector walks
all expressions owned by a consumed statement, including nested structured
bodies, so each synthesized comment receives one sorted, deduplicated union of
the machine instructions it replaces.

## Focused RED/GREEN evidence

The AArch64 split-GOT contract was extended with independent origins on its GOT
symbol, dereferences, saved address, stack destination, comparison, and failure
target. Before the production repair it remained five statements instead of
collapsing. After the repair:

```text
cargo test --features python-ext --lib \
  ir::canary::tests::structured_aarch64_got_canary_epilogue_collapses_with_its_save --quiet
1 passed; 0 failed

cargo test --features python-ext --lib ir::canary::tests --quiet
24 passed; 0 failed
```

No broad Rust or Python suite ran for this bounded change.

## Exact release fixture evidence

Commit `1e6f4743` was built in a detached clean worktree with a cache-backed
target directory. The build guard reported `fresh` and Python imported the
extension from that exact worktree. Only the directly affected real-binary
checks ran:

```text
python tools/dectest.py \
  20_graph_bfs:gcc:O2:graph_bfs --arch aarch64 --show
SCOPED: 1 lane of 3304 (0%) - no regressions in scope

python -m pytest -q \
  python/tests/test_decompiler_arch_roundtrip.py::test_aarch64_o2_stack_protected_functions_return_through_their_canary
2 passed
```

The periodic Hello grid was not repeated here because the immediately preceding
WP3 identity increments already retained selected O2 cells on x86-64, AArch64,
and ARMv7, and the last full checkpoint is 72/72. Continue to sample Hello at
coherent intervals rather than paying that unrelated grid for every
expression-consumer repair.

## Boundary

This closes the canary expression-consumer slice only. The remaining enabled
wildcard consumers and universal production expression attribution keep WP3
open.
