# WP3 typed constant folding requires identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `99843238` deletes the spelling-only entry points for redundant
declared-view folding and matching comparison-extension folding. Their
recursive implementations now require `ValueIdentities` rather than accepting
an optional sidecar. Production already owned the sidecar; this removes an
alternate semantic route that could silently restore display-name authority.
Legacy unit contracts now construct explicit parameter and promoted-object
identities and exercise the production entry points.

Untyped algebraic folding remains separate. It runs before typed declaration
facts are needed and does not use this declaration-width decision.

## Focused evidence

```text
ir::const_fold::tests:  82 passed, 0 failed
ir::widen::tests:       25 passed, 0 failed
decbench_ render tests: 86 passed, 0 failed
```

A fresh release build completed and `tools/build_guard.py` reported `fresh`
with native SHA-256
`a8f74257ceef8bb96c2e104bbe058f0a98b60914b633ee104a3f0d5baae625f8`.
The directly relevant `@widths` fixture set passed all four lanes with no scoped
regression. The six-cell cross-architecture Hello checkpoint passed on the
immediately preceding declaration-plan increment and was not repeated.

No test was added, so the census is unchanged. Other shared-worktree edits were
not staged. No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

This closes typed constant folding's identity-free declaration path. Typed
simplification, contextual widening, early copy propagation, and other explicit
compatibility surfaces remain separate WP3 migrations. `tag_phys` cannot yet be
removed.
