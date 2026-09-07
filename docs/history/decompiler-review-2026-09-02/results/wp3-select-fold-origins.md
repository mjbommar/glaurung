# WP3 select-fold origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `e92d7248` makes the destructive select-folding paths transparent to
statement origins. Attributed assignment diamonds, guarded select returns,
created-select return folding, and nested `try`/`catch` bodies now receive the
same semantic recovery as unattributed statements without losing the
instructions that justify the replacement.

This is a bounded WP3 wildcard-consumer migration. It does not add expression
origins, define non-contiguous source-line behavior, or complete authoritative
SSA consumer migration.

## Ownership and correctness boundary

Four tests were observed red before production changes:

- an attributed diamond did not collapse;
- an attributed select assignment did not fold into its adjacent return;
- an attributed initialized/guarded select did not recover direct returns; and
- an attributed `try` body was skipped by recursive select folding.

Origin ownership follows the semantic replacement rather than attaching one
undifferentiated set to the enclosing function:

- a collapsed diamond unions the original branch plus both arm assignments;
- a select folded into a return unions the assignment and return;
- the original outer guard remains on the recovered outer `if`;
- the selected assignment moves to the synthesized inner `if`; and
- the initializer and original joined return move to the trailing return.

The pass retains its existing fail-closed proofs: pure movable initializer,
same destination, promoted-local restriction, no self-dependence, and refusal
to collapse a result consumed only by an immediate return. `TryCatch` traversal
does not inherit a fallthrough result across the exception boundary.

## Evidence

Focused Rust coverage:

```text
cargo test --features python-ext select_fold::tests -- --nocapture
23 passed; 0 failed
```

Release build and complete stripped/debug differential:

```text
uv run maturin develop --release
uv run python tools/stripped_differential.py --jobs 8 --json
102 regressions; 17 improvements; 0 infrastructure problems
```

The 119-entry classification map is byte-for-byte identical to the preceding
vector-copy result. The gate exits 1 because the shared committed divergence
ratchet currently disagrees with that map; there is no attributable new or
removed stripped/debug classification in this increment.

The complete Rust gate is green:

```text
cargo test --features python-ext
library: 4,270 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored
all remaining integration and documentation targets passed
```

The mandatory post-commit whole Python suite completed red in 47 minutes 14
seconds:

```text
218 failed; 4,587 passed; 77 skipped; 128 deselected; 876 xfailed
```

Against the exact 221-node vector-copy boundary, normalized node IDs show zero
added failures and three removed failures:

- `test_real_arm_mixed_hard_float_spills_preserve_source_parameter_order`;
- `test_nested_conditional_result_recovers_direct_returns`; and
- `test_signs_renders_lifted_select_as_pure_ternary[-O0]`.

A controlled release A/B reversed only `e92d7248`, rebuilt, and ran those three
nodes before restoring the exact file hash and rebuilding the tip. The parent
was `FFF`; the tip was `...`. The ARM case is behavioral, not merely textual:
the parent rebuilt program printed `1.25 -3.5` instead of the reference
`1.25 -1.25`; the tip matches the reference. This proves all three removals are
attributable to the semantic transparency repair rather than shared-checkout
movement.

The current whole suite still contains no undeclared-local invariant failure.

## Next ordered increment

Re-audit the remaining enabled AST pass surface for raw wildcard consumers.
If that audit is closed, move from statement-carrier transparency to the next
WP3 requirement: expression ownership and an explicit non-contiguous
fold/hoist/duplication policy before exposing structured Python line mappings.
