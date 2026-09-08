# WP3 lazy-call-select origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `b84c03e5` closes the next enabled statement-origin consumer as one
coherent WP3 batch. `src/ir/lazy_call_select.rs` now sees through provenance
carriers when it inventories call results, recurses through structured bodies,
finds inertly separated consumers, counts gotos, and recognizes structured,
linearized, or conditional-jump call diamonds.

Every replacement keeps the deterministic union of the statements it consumes.
That includes the effectful call, its assignment or return, intervening no-ops,
the enclosing conditional, branch-local transfers, and drained labels/gotos.
The pass still moves rather than copies an eligible call and retains all prior
single-use, effect, join-uniqueness, saturation, and pointer-width refusals.

## Focused TDD

Five provenance cases were observed red before the production repair:

```text
attributed_adjacent_call_and_return_fold_with_all_consumed_origins
attributed_structured_call_diamond_folds_with_all_consumed_origins
attributed_conditional_jump_diamond_folds_with_drained_origins
attributed_linearized_diamond_folds_with_all_consumed_origins
attributed_outer_statement_does_not_hide_nested_call_diamond
```

The completed module and cross-module origin slice pass:

```text
cargo test --features python-ext ir::lazy_call_select::tests -- --nocapture
18 passed; 0 failed; 4,289 filtered out; 0.20 s test execution

cargo test --features python-ext origin --lib -- --nocapture
58 passed; 0 failed; 4,249 filtered out; 0.21 s test execution
```

## Release real-binary evidence

After `uv run maturin develop --release`, the host-compiled and stripped lazy
call select test passes. Fixture 189's effect witnesses and pure control all
remain green in GCC and Clang at O0 and O2:

```text
uv run pytest -q python/tests/test_decompiler_lazy_call_select.py
1 passed

uv run python tools/dectest.py 189_effectful_select --full --jobs 4
20 functions passed across 4 lanes; no regression in scope
```

The two indirect-tail/table-dispatch tests restored by the preceding call-
analysis batch also pass after rebuilding this tip, confirming that the A/B
extension was restored before measuring this increment.

## Broad gates

The complete Rust gate passes:

```text
cargo test --features python-ext
library: 4,307 passed; 0 failed; 5 ignored
identity retrieval: 44 passed; 0 failed; 10 ignored; 558.59 s
all remaining integration and documentation targets passed
```

The mandatory whole-Python post-commit gate completed in 44 minutes 32 seconds:

```text
uv run pytest python/tests/
210 failed; 4,596 passed; 76 skipped; 128 deselected; 876 xfailed
```

The prior accepted boundary has 209 exact failing node IDs. All 209 remain, and
one newly exercised i386 frame-array stack-protector invariant is added. A
release parent/tip A/B reproduces that exact failure at parent `3c0eed88` and
tip `b84c03e5`, so it is not attributable to this batch. The completed-run
`lastfailed` cache contains one additional stale node whose test was removed by
concurrent work and is not part of the 210 terminal failures. The attributable
delta is therefore zero added and zero removed.

## Next ordered increment

Re-audit the remaining enabled statement consumers, then start WP3 expression
ownership and the non-contiguous-transformation policy. Do not broaden this
origin migration into stack promotion, SplitBanks, or fixture-specific type
work owned by concurrent lanes.
