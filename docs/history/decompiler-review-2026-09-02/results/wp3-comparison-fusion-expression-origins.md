# WP3 comparison-fusion expression origins

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `edd529a6` makes comparison fusion transparent to expression-origin
carriers. Attributed flag-test trees, cast shells, constants, and proof-only
definitions remain eligible for the same width-checked fusion as semantic
expressions without provenance.

When several flag comparisons become one source comparison, the synthesized
predicate receives the deterministic union of every consumed expression owner.
Origin carriers are normalized rather than nested. Existing soundness
boundaries remain unchanged: mismatched widths or values, unproved unsigned
views, wrapping ranges, mutable aliases, and unsupported expressions still
decline.

This is a bounded WP3 expression-consumer migration. It does not complete
universal expression attribution, authoritative SSA/invalidation, the general
WP7B idiom framework, or WP3.

## Focused verification

The attributed flag-tree contract was observed red first because the outer
carrier prevented traversal and the attributed comparisons prevented matching.
After the repair:

```text
cargo test --features python-ext --lib \
  ir::cmp_fusion::tests::attributed_flag_expression_fuses_and_unions_consumed_owners \
  -- --exact
1 passed; 0 failed; 4,701 filtered out

cargo test --features python-ext --lib 'ir::cmp_fusion::tests::' --quiet
21 passed; 0 failed; 4,681 filtered out
```

The complete module includes the earlier 64-to-32 width-soundness regression,
unsigned-range equivalence/refusal cases, and wide i386 comparison proofs.
Filtered tests were not executed.

## Release parent/tip boundary

Clean detached worktrees at parent `bfe777f0` and tip `edd529a6` were both
release-built. The tip build guard reported fresh with native SHA-256
`90c6f259025cf8143ace3cc04924b24188b9833663cf431b40eea1185d45562e`.

The directly owning signed-loop test has two parameters and covers GCC/Clang,
debug/stripped binaries, relational spelling, C syntax, and execution. Both
parameters fail identically at parent and tip:

```text
uv run pytest -q python/tests/test_classify_signed_loop.py
2 failed at bfe777f0
2 failed at edd529a6
```

Both compilers already render the intended `while (100 < n)` with no expanded
flag formula. The remaining failures are separate return-type/output debts:
GCC renders `unsigned long classify(...)`, while Clang retains unsigned casts
around `n` and `-1`. This increment is exactly neutral on those failures.

No full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the non-exhaustive expression-consumer audit. Keep the signed-loop
return inference and cast cleanup visible as WP6/WP7B closure work; do not
misclassify the clean loop predicate as evidence that the full fixture is
green.
