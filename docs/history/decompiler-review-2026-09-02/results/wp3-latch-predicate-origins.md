# WP3 latch-predicate origin propagation

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Commit `a807b2d0` makes the latch-predicate consumer transparent to statement
origins. Predicate folding now sees attributed predicate assignments, carried
value updates, and snapshots. Loop-entry and source-update coalescing likewise
recognise attributed assignments and while-like statements.

Each destructive rewrite preserves ownership: a removed predicate assignment
is merged into its `do`/`while` statement, a removed entry copy is merged into
the surviving loop, and a removed scratch-to-carrier installation is merged
into the loop it updates. The origin set remains sorted and deduplicated by the
existing `OriginSet` contract.

This is a bounded WP3 wildcard-consumer migration. It does not complete
expression ownership, structured Python line mappings, non-contiguous
transformation policy, or authoritative SSA migration.

## Correctness boundary

Origin wrappers are metadata, not executable statements. Candidate selection,
recursive descent, read/write checks, and register replacement therefore
inspect or mutate `semantic()` statements. The existing fail-closed proofs are
unchanged: the pass still requires one straight-line predicate definition, one
safe snapshot, no intervening conflicting read/write, and exact carrier/scratch
roles.

Three tests were observed red before the production changes. They cover the
three destructive rewrite families and assert both the semantic result and the
exact union of the removed and surviving statement origins.

## Evidence

Focused Rust coverage:

```text
cargo test --features python-ext latch_predicate::tests -- --nocapture
12 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

That result is exactly neutral against the preceding switch-ladder boundary.

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,264 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory post-commit whole Python gate completed red. Its short-summary
section lists 221 failures. The pytest cache contains 222 failing node IDs
because it retains one node that this run did not execute,
`test_shadow_batch_locally_declines_an_unavailable_function`; the cache total
must therefore not be reported as the current-run failure count.

No latch-predicate, undeclared-local, guard-chain, switch-ladder,
guarded-switch, or effectful-loop node appears in either set. One guarded-call
node remains. The shared worktree contained concurrent uncommitted dataflow,
metrics, syntax, binding, and census changes throughout, so the broad Python
result and the separately observed 8/8 undeclared-local recovery are not
attributed to `a807b2d0`.

## Next ordered increment

Continue the wildcard audit before expression ownership. The first confirmed
omission is `src/ir/aapcs64_indirect_result.rs`: its enabled pre- and
post-stack-promotion readers still match raw statements, so attributed AAPCS64
`x8` and SysV hidden-result-buffer evidence can become invisible. Migrate that
consumer red-first, preserve statement ownership on mutation, and rerun the
same byte-neutral gates.
