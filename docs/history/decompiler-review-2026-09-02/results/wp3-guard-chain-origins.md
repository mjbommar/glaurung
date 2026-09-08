# WP3 guard-chain origin propagation

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `f7b47953` makes every production rewrite in `src/ir/guard_chain.rs`
transparent to statement-origin wrappers. Contradictory nested-guard pruning,
nested and matching terminal returns, paired terminal guards, redundant-copy
guards, shared assignments, and shared-exit ladders now inspect semantic
statements and preserve deterministic origin unions on synthesized or surviving
statements.

This is a bounded WP3 wildcard-consumer migration. It does not complete
expression origins, structured Python line mappings, authoritative SSA consumer
migration, or the remaining switch-ladder and latch-predicate consumers.

## Correctness boundary

Origin wrappers remain metadata rather than control-flow nodes. Recognition,
target counting, unstructured-transfer checks, and recursive descent therefore
use `semantic()` or `semantic_mut()` without weakening any existing shape,
purity, target-ownership, or exact-boolean precondition.

When a rewrite removes multiple guards, gotos, labels, duplicate assignments,
or duplicate terminal tails, their origins are unioned canonically into the
replacement. Statements retained in an exit or continuation keep their own
origins. The tests first reproduced each attributed failure before the
production migration.

## Evidence

Focused Rust coverage:

```text
cargo test --features python-ext guard_chain::tests -- --nocapture
25 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

That result is exactly neutral against the preceding guarded-switch boundary.

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,261 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The required post-commit whole Python gate completed red with exit status 1.
Its pytest cache records 224 failing node IDs in the shared checkout, compared
with 227 at the preceding recorded boundary. No guard-chain, guarded-switch, or
effectful-loop node is present. One guarded-call node remains red because an
earlier SSA/dataflow stage loses the call-result value before that consumer.
Concurrent uncommitted dataflow, metrics, syntax, binding, and census work was
present throughout this run, so the three-node reduction is not attributed to
`f7b47953` alone.

The separately reported undeclared-local regression was also checked directly
against this current release-built shared state:

```text
uv run pytest python/tests/test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared -q
8 passed
```

That recovery belongs to the overlapping stack/dataflow lane, not to the
guard-chain commit. The broad canonical-output, architecture,
generated-reference, baseline-ratchet, and known-defect groups remain open;
this result is not global repository closure.

## Next ordered increment

Continue the wildcard audit in `src/ir/switch_ladder.rs`, preserving origins
through recognition, recursive mutation, duplicated tails, and synthesized
switch/control nodes without weakening ownership proofs. Then migrate
`src/ir/latch_predicate.rs` before moving to expression ownership and structured
line mappings.
