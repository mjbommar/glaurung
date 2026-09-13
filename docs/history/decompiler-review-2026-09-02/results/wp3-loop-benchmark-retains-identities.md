# WP3: loop benchmark retains identities

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `6d98184c` migrates the isolated loop-recovery stage in
`benches/ir_structure.rs` from raw `promote_for_loops` to
`promote_for_loops_with_identities`. Both its micro lane and shape sweep now
retain the same `ValueIdentities` snapshot already owned by each prepared
fixture stage.

The benchmark no longer measures a legacy display-spelling decision where
production uses promoted-stack identity. Its existing AST clone remains the
only per-iteration mutable setup; the identity snapshot is read-only.

## Focused evidence

```text
cargo check --features python-ext --bench ir_structure
exit 0
```

No timing run or output comparison was performed, so this record makes no
performance or quality claim. No `src/` file changed, so the post-source-commit
Python gate did not apply. No fixture matrix, DecBench, Joern, or corpus sweep
was run.

## Remaining boundary

The public no-sidecar AST preparation APIs deliberately retain explicit legacy
compatibility semantics. WP3 remains open pending classification of the
remaining shipped raw consumers, conservative invalidation, and universal
origin preservation.
