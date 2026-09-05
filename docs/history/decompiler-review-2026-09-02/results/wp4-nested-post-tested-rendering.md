# WP4 nested post-tested loop rendering

> **Kind:** record · **Date:** 2026-09-04

## Result

Commit `80f5d1065e4ef0a74965b46796a4c14c2b7088f5` preserves ordinary
conditional regions inside post-tested loops instead of flattening their arms
into unconditional block sequences. The adapter absorbs only the exact typed
`Continue(header)` / `Break(exit)` latch pair into `do ... while`; other
conditionals remain `if`, and current-loop exits remain `break`.

A nested post-tested loop whose lexical continuation is absent now
materializes its exit block after the loop only when LLIR proves that block is
a complete unconditional-return tail. A nonterminal exit declines rendering
instead of emitting a path that falls off without its remaining owned region.
This is deliberately fail-closed and keeps v1 as production authority.

## Tests

Focused structure-v2 gate:

```bash
cargo test --features python-ext --lib structure_v2
```

Result: 37 passed, 0 failed. The real
`03_loop_shapes-gcc-O0.so::dowhile_atleastonce` fixture requires `do`, its
nested `if`, and `break` in parseable prepared C. A direct unit test proves a
materialized unconditional-return exit is accepted and an otherwise identical
`Nop` exit is rejected.

Required full Rust gate:

```bash
cargo test --features python-ext
```

Result: green. The library reported 4,017 passed, 0 failed, and 5 ignored;
every integration target passed, including the 44-pass / 10-ignored identity
retrieval target, and doc tests reported 2 passed and 1 ignored.

Required post-source-commit Python gate:

```bash
uv run pytest python/tests/ --tb=short -q
```

Result: terminal exit 1, so the global Python gate is **red**. The terminal
output exceeded the orchestration capture limit; no exact aggregate is claimed
from the truncated output. The complete failure-name tail identified failures
across analyst locals and declarations, build configurations, ARM32 execution,
control-flow and def-use invariants, dialect parsing, emission invariants,
fixture and structural baselines, generated references, fitness limits,
documentation indexing, and test-census drift. The focused structure-v2 gate
and the pinned execution comparison above remain the behavioral evidence for
this increment; they do not replace or relabel the global red gate.

## Pinned corpus evidence

Commands:

```bash
uv run maturin develop --release
uv run python tools/structure_v2_compare.py --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-80f5d106.json"
uv run python tools/structure_v2_execution.py \
  "$HOME/.cache/glaurung/tmp/structure-v2-80f5d106.json" --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-execution-80f5d106.json"
```

Both reports identify revision
`80f5d1065e4ef0a74965b46796a4c14c2b7088f5`.

Structural comparison over 715 requested functions in 436 built objects:

- 262 improved, 68 unchanged, 4 raw regressed, and 381 shadow declined;
- all four raw regressions satisfy the exact reviewed honest-goto contract;
  unexplained regressions are zero;
- comparable gotos: production 2,475, shadow 559;
- comparable bytes: production 1,162,137, shadow 1,736,509;
- summed time: production 60.30s, shadow 59.36s;
- wall time 29.97s; peak RSS 890,724 KiB.

Execution comparison over 334 candidates in 214 executable objects:

- 14 improved, 246 stable pass, and 29 stable non-pass;
- **0 regressed** and 0 infrastructure findings;
- 45 explicitly not executable by the harness;
- summed time: production 139.19s, shadow 108.96s;
- wall time 62.59s.

The 45 non-executable candidates remain unproved, not passes. The larger
current build inventory also changes the comparable production denominator, so
the aggregate byte and goto totals must not be compared as percentages against
older reports with a different rendered-candidate set.

## Roadmap effect

This completes immediate action 1 and strengthens WP4's execution criterion,
but it is not WP4 promotion. Pinned GED, the structure-axis score, explicit
block/edge-accounting closure, and accepted runtime/output-size budgets remain
open before v2 can become the production default.
