# WP3 typed-comparison expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `251ae25e` makes `fold_typed_comparison_extensions` transparent to
outer-cast, inner-cast, and source expression-origin carriers. A comparison
whose declaration facts justify removing matching signed or unsigned
extensions now leaves the surviving source-width operand with the canonical
union of all three owners. Equality still retains the exact-width inner cast;
ordered comparisons still require authoritative source declarations.

The shared mixed-view terminal-relation consumer also includes those cast
owners when it synthesizes the readable signed comparison. Existing width,
signedness, declaration, and return-promotion refusals are unchanged. This is
one bounded constant-fold consumer migration, not completion of WP3.

## Focused verification

The strengthened six-owner comparison test was observed red first because the
raw matcher did not see through the outer cast carriers. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::typed_comparison_views_preserve_cast_and_source_origins \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
76 passed; 0 failed; 4,302 filtered out; 0.02 s
```

Filtered tests were not executed. The module run includes the width,
signedness, declaration, terminal-relation, and checked-in real-binary
controls. No full Rust, Python, fixture, architecture, DecBench, or Joern suite
was run.
