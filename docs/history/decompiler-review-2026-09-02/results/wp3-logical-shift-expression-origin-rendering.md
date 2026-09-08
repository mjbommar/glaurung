# WP3 logical-shift expression-origin rendering

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `76360517` makes the logical-right-shift renderer inspect the semantic
left operand when deciding whether an unsigned width cast is already present.
An `OriginSet` around `(unsigned int)arg0` therefore no longer produces the
redundant spelling `(unsigned int)((unsigned int)arg0)`.

The change does not alter width inference, shift-count handling, or cast
semantics. A four-byte load continues to shift as `unsigned int`, and the
separate wide-left-shift repair continues to preserve its narrow source view
before widening.

## Focused TDD

The new exact contract was observed red as:

```text
return ((unsigned int)((unsigned int)(arg0)) >> 8);
```

After changing only the existing `stated`-cast recognizer to use the semantic
view, the owning contract and its two adjacent width guards pass:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::decbench_logical_shift_does_not_repeat_an_attributed_unsigned_cast \
  -- --exact
1 passed; 0 failed; 4,673 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::decbench_logical_shift_uses_the_exact_load_width -- --exact
1 passed; 0 failed; 4,673 filtered out

cargo test --features python-ext --lib \
  ir::ast::tests::decbench_wide_left_shift_keeps_declared_narrow_operand_through_origins \
  -- --exact
1 passed; 0 failed; 4,673 filtered out
```

## Release real-binary evidence

After the required release rebuild, the two exact Rust shift-family cells both
pass on the concurrent shared snapshot:

```text
uv run python tools/dectest.py \
  171_rust_overflow:rustc:O0:rust_shift_family \
  171_rust_overflow:rustc:O2:rust_shift_family --show
2 cells pass; no scoped regressions
```

The harness reported the O0 cell as a baseline improvement. A controlled
one-line A/B rebuilt the same shared snapshot with only this renderer decision
reverted; the identical O0 improvement remained. That status change is
therefore not attributable to this increment and no baseline was refreshed.

## Scope

This is a bounded WP3 rendering consumer. It removes redundant scored-text
structure while preserving the exact machine-width proof. It does not change
shift recovery, Rust semantics, or universal expression attribution.
