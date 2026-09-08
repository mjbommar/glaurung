# WP3 switch-ladder origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `3b7d8a95` makes every production path in
`src/ir/switch_ladder.rs` transparent to statement-origin wrappers. Nested GCC
comparison trees, linear labelled dispatches, label/goto ownership proofs,
terminal-transfer checks, recursive switch discovery, shared-default matching,
and final join-to-`break` cleanup now operate on semantic statements.

Recovered switches own the canonical union of the comparison, dispatch, case,
goto, label, and join statements consumed by the rewrite. A goto rewritten as
a source-level `break` retains that goto's exact origins. Retained case and
default statements keep their own carriers.

This is a bounded WP3 wildcard-consumer migration. It does not complete
expression origins, structured Python line mappings, authoritative SSA consumer
migration, or the remaining latch-predicate consumer.

## Correctness boundary

Origin wrappers are metadata, not control-flow nodes. The existing recovery
proofs remain unchanged: one discriminant, unique reachable case constants,
one proven default, exact goto/reference counts, case bodies ending in
unconditional transfer, and adjacency before a join goto becomes `break`.
Only wrapper visibility and deterministic attribution changed.

Three tests were observed red before their production migrations. They cover an
attributed existing switch with a conditional join goto, an attributed nested
GCC comparison tree, and an attributed linear labelled dispatch. Each asserts
both semantic recovery and the exact expected origin set.

## Evidence

Focused Rust coverage:

```text
cargo test --features python-ext switch_ladder::tests -- --nocapture
28 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

That result is exactly neutral against the preceding guard-chain boundary.

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,264 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The required post-commit whole Python gate completed red with exit status 1.
Its pytest cache records 222 failing node IDs in the shared checkout, compared
with 224 at the preceding recorded boundary. No switch-ladder, guard-chain,
guarded-switch, effectful-loop, or undeclared-local node is present. One
guarded-call node remains red because an earlier SSA/dataflow stage loses the
call-result value before that consumer. Concurrent uncommitted dataflow,
metrics, syntax, binding, and census work was present throughout this run, so
the two-node reduction is not attributed to `3b7d8a95` alone.

The broad canonical-output, architecture, generated-reference,
baseline-ratchet, and known-defect groups remain open; this result is not global
repository closure.

## Next ordered increment

Migrate `src/ir/latch_predicate.rs` as the next wildcard consumer. Recognition,
recursive descent, mutation, and any synthesized loop predicate must see
through statement origins and preserve the canonical union of every consumed
contributor. Then re-audit the production wildcard surface before moving to
expression ownership and structured line mappings.
