# WP4 source-level loop continuation recovery

> **Kind:** record · **Date:** 2026-09-04

## Result

Commit `85a6169378939603a87e7cfb4fac68763f023bdf` replaces a retained edge to
the current multi-exit loop header with a first-class AST `Continue`. The
lowerer descends only through conditionals and switches for this rewrite; it
does not cross a nested-loop boundary. This makes `continue;` valid even when
the transfer is inside a switch, while the outermost terminal backedge remains
an implicit loop continuation.

This closes the nine unexplained structural regressions recorded at
`c3bbe2a6` without deleting a required transfer. All AST consumers were updated
explicitly. Expression and naming passes preserve `Continue` as an
expression-free statement; copy and stack-coordinate analyses treat it as a
control-flow boundary.

## Tests

Focused typed-transfer tests:

```bash
cargo test --features python-ext multi_exit_transfer_tests --no-fail-fast
```

Result: 3 passed, 0 failed. The tests prove that only the outermost terminal
backedge may disappear, while nested conditional and switch-arm backedges
become `Continue`.

Real-fixture shadow coverage:

```bash
cargo test --features python-ext structure_v2 --no-fail-fast
```

Result: 36 passed, 0 failed. The fixture contracts now require `continue;` and
require the corresponding unreferenced loop-header labels to be pruned.

The required full Rust gate was also run:

```bash
cargo test --features python-ext
```

The library reported 4,015 passed, 5 ignored, and one failure in the separate
uncommitted `src/csource/lower/` lane:
`csource::lower::ctype::tests::float_and_aggregate_types_are_named_not_lowered`
expected `Some(Aggregate("struct"))` and received `None`. Therefore the global
Rust gate is **red** in the shared working tree; it is not reported as a pass
for this increment.

## Pinned corpus evidence

Commands:

```bash
uv run maturin develop --release
uv run python tools/structure_v2_compare.py --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-85a61693.json"
uv run python tools/structure_v2_execution.py \
  "$HOME/.cache/glaurung/tmp/structure-v2-85a61693.json" --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-execution-85a61693.json"
```

Both reports identify revision
`85a6169378939603a87e7cfb4fac68763f023bdf`.

Structural comparison over 715 requested functions in 436 built objects:

- 220 improved, 26 unchanged, 4 raw regressed, and 465 shadow declined;
- all four raw regressions satisfy the existing exact honest-goto contract;
  unexplained regressions are zero;
- comparable gotos: production 1,790, shadow 324, down from shadow 584 at
  `c3bbe2a6`;
- comparable bytes: production 693,393, shadow 1,216,193;
- summed time: production 50.91s, shadow 43.19s;
- wall time 23.63s; peak RSS 886,836 KiB.

Execution comparison over 250 candidates in 166 executable objects:

- 12 improved, 177 stable pass, and 22 stable non-pass;
- **0 regressed** and 0 infrastructure findings;
- 39 explicitly not executable by the harness;
- summed time: production 120.55s, shadow 86.00s;
- wall time 51.98s.

The 39 non-executable candidates remain unproved, not passes. WP4 also remains
in shadow mode: nested post-tested rendering, block/edge accounting, GED,
structure-axis movement, and accepted runtime/output-size budgets are still
promotion requirements.
