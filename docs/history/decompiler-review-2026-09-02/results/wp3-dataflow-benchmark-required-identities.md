# WP3 dataflow benchmark requires identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `e44ebdc8` migrates the remaining non-test benchmark callers of early
copy propagation and constant folding to authoritative `ValueIdentities`.
`benches/ir_dataflow.rs` already loads real fixture binaries, performs SSA and
value numbering, and lowers the numbered function. It previously discarded
the identity sidecar and then measured spelling-based compatibility APIs.

The benchmark now retains that sidecar in each prepared subject and threads it
through:

- every AST prefix used by the micro-pass measurements;
- the individual constant-fold and copy-propagation lanes;
- the composed AST-dataflow lane; and
- the bounded copy/constant fixpoint lane.

The typed fixpoint and constant-fold entry points are public because Criterion
bench targets compile as a separate crate. The production pipeline continues
to call the same implementations internally.

## Focused evidence

The first benchmark compile exposed that the typed fixpoint was not exported
and that typed constant folding was crate-private. After making those explicit
typed APIs available:

```text
prepare::fixpoint_tests:              4 passed, 0 failed
ir::const_fold::tests:               82 passed, 0 failed
ir::copy_prop::tests:                38 passed, 0 failed
cargo check --features python-ext
  --bench ir_dataflow:                passed
cargo bench --bench ir_dataflow
  --no-run:                           passed
```

`uv run maturin develop` completed and `tools/build_guard.py` reported
`fresh`, with native SHA-256
`19fbd852eaf78f6989db7259488329225dcd1438cd26420b53593bcc0b5c3d57`.
The extension includes concurrent unstaged shared-worktree changes, so it is
live-tree build evidence rather than an exact-clean-checkout artifact.

No benchmark timing or product-output gain is claimed. This makes subsequent
timings representative of the shipped semantic route. No test census changes.
No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

No benchmark now invokes spelling-based vector recovery, copy propagation,
constant folding, or their bounded fixpoint. The remaining no-sidecar calls
are the explicit public diagnostic/test preparation surface, including the
legacy structure-v2 text view. The next WP3 audit should distinguish whether
that surface is supported library behavior or can be narrowed to test/review
compatibility before `tag_phys` removal. WP3 remains incomplete.
