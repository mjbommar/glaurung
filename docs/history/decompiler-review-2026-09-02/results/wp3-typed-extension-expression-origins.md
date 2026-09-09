# WP3 typed-extension expression origins

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `626b94c5` makes type-directed consumed-extension cleanup transparent to
expression-origin carriers. A recovered narrow destination can therefore still
remove an unobservable machine-parent zero extension after expression
attribution is enabled.

When the outer machine-width cast disappears, its owner and the retained inner
cast owner are unioned on the surviving narrow cast. The enclosing modular
operation keeps its own separate owner. Signed inner views, lone extensions,
division, shifts, unproved destinations, and all existing fail-closed
boundaries remain unchanged.

This is one bounded WP3 expression-consumer migration, not universal expression
attribution, authoritative SSA completion, or WP3 completion.

## Focused verification

The attributed contract was observed red first: the origin carrier prevented
the raw cast matcher from firing. After the repair:

```text
cargo test --features python-ext --lib \
  ir::typed_simplify::tests::attributed_machine_extension_folds_and_preserves_consumed_origins \
  -- --exact
1 passed; 0 failed; 4,700 filtered out

cargo test --features python-ext --lib 'ir::typed_simplify::tests::' --quiet
6 passed; 0 failed; 4,695 filtered out
```

A clean detached worktree at exact commit `626b94c5` was release-built. Its
build guard reported fresh with native SHA-256
`104a4f6d04ce5132e5c2532dbade193f8dc15f3882f97375e5b2bc57e086ddb8`.
The directly owning narrow-width fixture remained green:

```text
uv run python tools/dectest.py \
  '194_narrow_return_widths:*:*:nrw194_u8_mix' --jobs 2 --full --show
4 passed across Clang/GCC O0/O2; no regressions in scope
```

Filtered Rust tests were not executed. No full Rust, Python, fixture,
architecture, DecBench, or Joern suite was run.

## Next boundary

Continue the non-exhaustive expression-consumer audit with the next production
constructor that removes or replaces attributed operands. Preserve exact
consumed-owner composition and validate only its module plus the smallest
directly owning real-binary slice.
